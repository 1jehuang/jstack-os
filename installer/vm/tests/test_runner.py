from __future__ import annotations

import importlib.util
import contextlib
import hashlib
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
LAB_SPEC = importlib.util.spec_from_file_location("jstack_vm_runner_lab", ROOT / "lab.py")
assert LAB_SPEC and LAB_SPEC.loader
lab = importlib.util.module_from_spec(LAB_SPEC)
LAB_SPEC.loader.exec_module(lab)
sys.modules["lab"] = lab
RUNNER_SPEC = importlib.util.spec_from_file_location("jstack_vm_runner", ROOT / "runner.py")
assert RUNNER_SPEC and RUNNER_SPEC.loader
runner = importlib.util.module_from_spec(RUNNER_SPEC)
RUNNER_SPEC.loader.exec_module(runner)


class RunnerSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "scratch"
        self.root.mkdir(mode=0o700)
        self.workspace = self.root / "jstack-windows-vm"
        self.workspace.mkdir(mode=0o700)
        for name in ("images", "runs", "evidence"):
            (self.workspace / name).mkdir(mode=0o700)
        self.pins: list[runner.PinnedFile] = []

    def tearDown(self) -> None:
        for pinned in self.pins:
            pinned.close()

    def pin(self, path: Path, data: bytes = b"data", *, writable: bool = False) -> runner.PinnedFile:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(data)
        pinned = runner._open_pinned(path, writable=writable, label=path.name)
        self.pins.append(pinned)
        return pinned

    def test_secure_open_rejects_symlink_components_and_special_files(self) -> None:
        real = self.workspace / "images" / "real"
        real.mkdir()
        regular = real / "disk.qcow2"
        regular.write_bytes(b"qcow")
        linked = self.workspace / "images" / "linked"
        linked.symlink_to(real, target_is_directory=True)
        with self.assertRaises((lab.LabSafetyError, OSError)):
            lab.open_regular_nofollow(linked / regular.name)

        fifo = self.workspace / "images" / "fifo"
        os.mkfifo(fifo)
        with self.assertRaises(lab.LabSafetyError):
            lab.open_regular_nofollow(fifo)

    def test_workspace_file_policy_rejects_hardlinks_symlinks_and_devices(self) -> None:
        original = self.workspace / "images" / "disk.qcow2"
        original.write_bytes(b"qcow")
        hardlink = self.workspace / "images" / "hardlink.qcow2"
        os.link(original, hardlink)
        symlink = self.workspace / "images" / "symlink.qcow2"
        symlink.symlink_to(original)
        for unsafe in (original, hardlink, symlink, Path("/dev/null")):
            with self.subTest(path=unsafe):
                with self.assertRaises(lab.LabSafetyError):
                    runner._regular_path(
                        unsafe, label="VM disk", suffix=".qcow2", workspace=self.workspace
                    )

    def test_qcow2_backing_chain_is_pinned_and_cannot_escape_workspace(self) -> None:
        overlay = self.workspace / "images" / "overlay.qcow2"
        base = self.workspace / "images" / "base.qcow2"
        outside = self.root / "outside.qcow2"
        for path in (overlay, base, outside):
            path.write_bytes(path.name.encode())
        base.chmod(0o444)

        with mock.patch.object(
            runner,
            "_qcow2_info",
            side_effect=[{"backing-filename": "base.qcow2"}, {}],
        ):
            chain = runner.validate_and_pin_qcow2(overlay, self.workspace, Path("qemu-img"))
        self.pins.extend(chain)
        self.assertEqual([item.path for item in chain], [overlay, base])
        self.assertTrue(chain[0].writable)
        self.assertFalse(chain[1].writable)

        with mock.patch.object(
            runner, "_qcow2_info", return_value={"backing-filename": str(outside)}
        ):
            with self.assertRaisesRegex(lab.LabSafetyError, "remain below workspace"):
                runner.validate_and_pin_qcow2(overlay, self.workspace, Path("qemu-img"))

    def test_qemu_img_validation_uses_only_the_pinned_fd_and_clean_environment(self) -> None:
        disk = self.pin(self.workspace / "images" / "disk.qcow2")
        completed = mock.Mock(stdout='{"format":"qcow2"}')
        with mock.patch.object(runner.subprocess, "run", return_value=completed) as run:
            runner._qcow2_info(disk, Path("/usr/bin/qemu-img"))
        arguments = run.call_args.args[0]
        self.assertEqual(arguments[-1], f"/proc/self/fd/{disk.descriptor}")
        self.assertEqual(run.call_args.kwargs["pass_fds"], (disk.descriptor,))
        environment = run.call_args.kwargs["env"]
        self.assertEqual(set(environment), {"HOME", "LANG", "LC_ALL", "PATH", "TMPDIR"})
        self.assertNotIn("LD_PRELOAD", environment)
        self.assertNotIn("QEMU_AUDIO_DRV", environment)

    def test_firmware_vars_copy_is_exclusive_hashed_and_durable(self) -> None:
        template = self.root / "OVMF_VARS.fd"
        template.write_bytes(b"firmware-template")
        run_directory = self.workspace / "runs" / "direct-qemu"
        run_directory.mkdir(mode=0o700)
        destination = run_directory / "ovmf-vars.fd"
        real_fsync = os.fsync
        with mock.patch.object(runner.os, "fsync", wraps=real_fsync) as fsync:
            facts = runner._copy_firmware_vars(template, destination)
        self.assertTrue(facts["created"])
        self.assertEqual(destination.read_bytes(), template.read_bytes())
        self.assertEqual(facts["template"]["sha256"], facts["copy"]["sha256"])
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
        self.assertGreaterEqual(fsync.call_count, 2)
        self.assertEqual(list(run_directory.glob(".ovmf-vars.fd.*.tmp")), [])

        destination.write_bytes(b"persisted-guest-state")
        with self.assertRaisesRegex(lab.LabSafetyError, "refusing to reuse"):
            runner._copy_firmware_vars(template, destination)

    def test_firmware_copy_refuses_existing_symlink(self) -> None:
        template = self.root / "OVMF_VARS.fd"
        template.write_bytes(b"template")
        run_directory = self.workspace / "runs" / "direct-qemu"
        run_directory.mkdir(mode=0o700)
        destination = run_directory / "ovmf-vars.fd"
        destination.symlink_to(template)
        with self.assertRaises(lab.LabSafetyError):
            runner._copy_firmware_vars(template, destination)

    def make_iso(self, name: str = "official.iso", *, cd001: bool = True) -> tuple[Path, dict[str, object]]:
        data = bytearray(16 * 2048 + 6)
        if cd001:
            data[16 * 2048 + 1 : 16 * 2048 + 6] = b"CD001"
        path = self.root / name
        path.write_bytes(data)
        return path, {
            "record_id": "official-media",
            "availability": "available",
            "iso": {
                "filename": name,
                "size_bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            },
        }

    def make_profile(self, scenario: dict[str, str]) -> dict[str, object]:
        input_ids = {
            "qemu-binary-sha256",
            "ovmf-code-sha256",
            "ovmf-nonsecure-code-sha256",
            "ovmf-enrolled-vars-sha256",
            "ovmf-fixed-vars-sha256",
            "swtpm-binary-sha256",
            "base-image-sha256",
            "base-image-gpt-sha256",
            "installer-sha256",
            "installer-graph-sha256",
            "release-manifest-sha256",
            "boot-artifacts-sha256",
        }
        return {
            "profile_id": "synthetic-exact-profile",
            "qemu": {
                "binary": "qemu-system-x86_64",
                "binary_sha256_input": "qemu-binary-sha256",
                "machine": {"type": runner.MACHINE},
                "version_constraint": {
                    "minimum_inclusive": "11.0.0",
                    "maximum_exclusive": "11.1.0",
                },
            },
            "compute": {
                "ram_bytes": runner.MEMORY_MIB * 1024 * 1024,
                "cpu": {"vcpus": runner.VCPUS},
            },
            "firmware": {
                "code": {
                    "canonical_name": "OVMF_CODE.secboot.4m.fd",
                    "sha256_input": "ovmf-code-sha256",
                },
                "nonsecure_code": {
                    "canonical_name": "OVMF_CODE.4m.fd",
                    "sha256_input": "ovmf-nonsecure-code-sha256",
                },
                "enrolled_vars": {
                    "canonical_name": "OVMF_VARS.ms-enrolled.4m.fd",
                    "sha256_input": "ovmf-enrolled-vars-sha256",
                },
                "fixed_vars": {
                    "canonical_name": "OVMF_VARS.4m.fd",
                    "sha256_input": "ovmf-fixed-vars-sha256",
                },
            },
            "security": {
                "tpm": {
                    "absent_variant_permitted": True,
                    "emulator": "swtpm",
                    "emulator_sha256_input": "swtpm-binary-sha256",
                    "emulator_version_constraint": {
                        "minimum_inclusive": "0.10.0",
                        "maximum_exclusive": "0.11.0",
                    },
                }
            },
            "storage": {
                "base_image_sha256_input": "base-image-sha256",
                "base_image_gpt_sha256_input": "base-image-gpt-sha256",
                "virtual_size_bytes": 137438953472,
                "controller": "nvme",
                "serial": "JSTACKLAB0001",
                "logical_sector_bytes": 512,
                "physical_sector_bytes": 4096,
            },
            "artifacts": {
                "installer_sha256_input": "installer-sha256",
                "installer_graph_sha256_input": "installer-graph-sha256",
                "release_manifest_sha256_input": "release-manifest-sha256",
                "boot_artifacts_sha256_input": "boot-artifacts-sha256",
            },
            "network": {
                "controller": "e1000e",
                "backend": "user",
                "mac_address": "52:54:00:4a:53:01",
                "host_forwarding": "disabled",
            },
            "required_inputs": [
                {
                    "id": input_id,
                    "type": "sha256",
                    "state": "required-unresolved",
                    "value": None,
                }
                for input_id in sorted(input_ids)
            ],
        }

    def prepare_synthetic_plan(
        self, scenario: dict[str, str], run_id: str, control_media=None
    ) -> runner.LaunchPlan:
        base = self.workspace / "images" / f"{run_id}-base.qcow2"
        base.write_bytes(b"immutable-base")
        base.chmod(0o444)
        iso, media = self.make_iso(f"{run_id}.iso")
        qemu = self.root / "qemu-system-x86_64"
        qemu_img = self.root / "qemu-img"
        swtpm = self.root / "swtpm"
        firmware_directory = self.root / f"{run_id}-firmware"
        firmware_directory.mkdir()
        secure_code = firmware_directory / "OVMF_CODE.secboot.4m.fd"
        nonsecure_code = firmware_directory / "OVMF_CODE.4m.fd"
        enrolled_vars = firmware_directory / "OVMF_VARS.ms-enrolled.4m.fd"
        fixed_vars = firmware_directory / "OVMF_VARS.4m.fd"
        base_gpt = self.root / f"{run_id}-base-gpt.bin"
        installer = self.root / f"{run_id}-installer.bin"
        installer_graph = self.root / f"{run_id}-installer-graph.json"
        release_manifest = self.root / f"{run_id}-release-manifest.json"
        boot_artifacts = self.root / f"{run_id}-boot-artifacts.bin"
        for path in (
            qemu,
            qemu_img,
            swtpm,
            secure_code,
            nonsecure_code,
            enrolled_vars,
            fixed_vars,
            base_gpt,
            installer,
            installer_graph,
            release_manifest,
            boot_artifacts,
        ):
            path.write_bytes(path.name.encode())
        profile = self.make_profile(scenario)
        files = {
            "qemu-binary-sha256": qemu,
            "ovmf-code-sha256": secure_code,
            "ovmf-nonsecure-code-sha256": nonsecure_code,
            "ovmf-enrolled-vars-sha256": enrolled_vars,
            "ovmf-fixed-vars-sha256": fixed_vars,
            "swtpm-binary-sha256": swtpm,
            "base-image-sha256": base,
        }
        resolved = {
            item["id"]: hashlib.sha256(item["id"].encode()).hexdigest()
            for item in profile["required_inputs"]
        }
        resolved.update(
            {input_id: hashlib.sha256(path.read_bytes()).hexdigest() for input_id, path in files.items()}
        )
        input_files = {
            "ovmf-enrolled-vars": enrolled_vars,
            "ovmf-fixed-vars": fixed_vars,
            "base-image-gpt": base_gpt,
            "installer": installer,
            "installer-graph": installer_graph,
            "release-manifest": release_manifest,
            "boot-artifacts": boot_artifacts,
        }
        input_roles = {
            "ovmf-enrolled-vars": "ovmf-enrolled-vars-sha256",
            "ovmf-fixed-vars": "ovmf-fixed-vars-sha256",
            "base-image-gpt": "base-image-gpt-sha256",
            "installer": "installer-sha256",
            "installer-graph": "installer-graph-sha256",
            "release-manifest": "release-manifest-sha256",
            "boot-artifacts": "boot-artifacts-sha256",
        }
        resolved.update(
            {
                input_roles[role]: hashlib.sha256(path.read_bytes()).hexdigest()
                for role, path in input_files.items()
            }
        )
        for path in input_files.values():
            path.chmod(0o444)

        def create_overlay(_base, overlay, _qemu_img, _workspace):
            overlay.write_bytes(b"fresh-overlay")

        def qcow_info(pinned, _qemu_img):
            if pinned.path.name == "disk-overlay.qcow2":
                return {"format": "qcow2", "backing-filename": str(base)}
            return {"format": "qcow2", "virtual-size": 137438953472}

        executables = [qemu, qemu_img, swtpm]
        with (
            mock.patch.object(lab, "require_scratch_root", return_value=self.root),
            mock.patch.object(lab, "reject_nested_mounts"),
            mock.patch.object(lab, "OVMF_SECURE_CODE", secure_code),
            mock.patch.object(lab, "OVMF_CODE", nonsecure_code),
            mock.patch.object(lab, "OVMF_VARS", fixed_vars),
            mock.patch.object(runner, "_resolve_profile", return_value=(profile, scenario, media)),
            mock.patch.object(runner, "_require_executable", side_effect=executables),
            mock.patch.object(runner, "_verify_machine"),
            mock.patch.object(runner, "_verify_version_constraint"),
            mock.patch.object(runner, "_create_overlay", side_effect=create_overlay),
            mock.patch.object(runner, "_qcow2_info", side_effect=qcow_info),
        ):
            return runner.prepare_launch(
                self.workspace,
                base,
                iso,
                profile_id=profile["profile_id"],
                scenario_id=scenario["id"],
                resolved_inputs=resolved,
                input_files=input_files,
                run_id=run_id,
                control_media=control_media,
            )

    def test_prepare_launch_emits_only_fixed_qemu_topology_and_fresh_fdsets(self) -> None:
        scenario = {
            "id": "secureboot-tpm-bitlocker-off",
            "secure_boot": "enabled",
            "tpm": "2.0",
            "bitlocker": "disabled",
        }
        plan = self.prepare_synthetic_plan(scenario, "fixed-topology")
        self.addCleanup(plan.close)
        argv = plan.qemu_argv
        self.assertIn("-nodefaults", argv)
        self.assertIn("-no-user-config", argv)
        self.assertIn("-S", argv)
        self.assertEqual(
            argv[argv.index("-machine") + 1],
            f"{runner.MACHINE},accel=kvm,pflash0=ovmf-code,pflash1=ovmf-vars",
        )
        self.assertNotIn("-drive", argv)
        self.assertNotIn("-hda", argv)
        self.assertNotIn(str(plan.disk_chain[1]), argv)
        self.assertEqual(plan.run_id, "fixed-topology")
        self.assertTrue(plan.evidence_directory.is_dir())
        self.assertTrue((plan.run_directory / "ovmf-vars.fd").is_file())
        self.assertTrue((plan.run_directory / "swtpm-state").is_dir())
        self.assertEqual(plan.disk_chain[0], plan.run_directory / "disk-overlay.qcow2")
        self.assertEqual(plan.pins[0].metadata.st_nlink, 1)
        self.assertFalse(plan.pins[1].metadata.st_mode & 0o222)
        device_values = [
            argv[index + 1]
            for index, value in enumerate(argv[:-1])
            if value == "-device"
        ]
        self.assertIn(
            "nvme,drive=disk-qcow-0,serial=JSTACKLAB0001,bootindex=1,"
            "logical_block_size=512,physical_block_size=4096",
            device_values,
        )
        self.assertIn("tpm-crb,tpmdev=tpm0", device_values)
        self.assertIn("VGA", device_values)
        self.assertNotIn("virtio-vga", device_values)
        self.assertNotIn("virtio-blk-pci", " ".join(argv))
        self.assertEqual(
            argv[argv.index("-nic") + 1],
            "user,model=e1000e,mac=52:54:00:4a:53:01",
        )
        self.assertNotIn("virtio-net-pci", " ".join(argv))
        self.assertTrue(
            all(
                "/dev/fdset/" in value
                for value in runner._qmp_paths(
                    [
                        {"filename": option}
                        for index, option in enumerate(argv)
                        if index and argv[index - 1] == "-blockdev" and "/dev/fdset/" in option
                    ]
                )
            )
        )
        self.assertEqual(
            plan.block_nodes,
            {
                "disk-file-0",
                "disk-qcow-0",
                "disk-file-1",
                "disk-qcow-1",
                "ovmf-code-file",
                "ovmf-code",
                "ovmf-vars-file",
                "ovmf-vars",
                "install-iso-file",
                "install-iso",
            },
        )
        self.assertTrue(plan.firmware_copy["created"])
        self.assertIn("sha256", plan.as_dict()["executables"]["qemu"])
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            runner.parser().parse_args(["dry-run", "--qemu-arg=-drive"])

    def test_secure_boot_and_tpm_variants_select_exact_firmware_and_state(self) -> None:
        cases = [
            ("enabled", "2.0", "OVMF_CODE.secboot.4m.fd", "OVMF_VARS.ms-enrolled.4m.fd"),
            ("disabled", "2.0", "OVMF_CODE.4m.fd", "OVMF_VARS.4m.fd"),
            ("disabled", "absent", "OVMF_CODE.4m.fd", "OVMF_VARS.4m.fd"),
        ]
        for index, (secure_boot, tpm, code_name, vars_name) in enumerate(cases):
            with self.subTest(secure_boot=secure_boot, tpm=tpm):
                scenario = {
                    "id": f"variant-{index}",
                    "secure_boot": secure_boot,
                    "tpm": tpm,
                    "bitlocker": "disabled",
                }
                plan = self.prepare_synthetic_plan(scenario, f"variant-{index}")
                self.addCleanup(plan.close)
                code_pin = next(item for item in plan.pins if item.label == "OVMF code")
                self.assertEqual(code_pin.path.name, code_name)
                self.assertEqual(Path(plan.firmware_copy["template"]["path"]).name, vars_name)
                self.assertEqual("-global" in plan.qemu_argv, secure_boot == "enabled")
                self.assertEqual(bool(plan.swtpm_argv), tpm == "2.0")
                self.assertEqual((plan.run_directory / "swtpm-state").exists(), tpm == "2.0")
                self.assertEqual("tpm-crb,tpmdev=tpm0" in plan.qemu_argv, tpm == "2.0")

    def test_iso_requires_exact_size_hash_and_iso_structure_not_local_filename(self) -> None:
        iso, media = self.make_iso("official.iso")
        pinned = runner._open_pinned(iso, writable=False, label="installation ISO")
        self.addCleanup(pinned.close)
        runner._validate_iso(pinned, media)

        synthetic = dict(media)
        synthetic["iso"] = dict(media["iso"], filename="different.iso")
        runner._validate_iso(pinned, synthetic)

        synthetic["iso"] = dict(media["iso"], size_bytes=iso.stat().st_size + 1)
        with self.assertRaisesRegex(lab.LabSafetyError, "size"):
            runner._validate_iso(pinned, synthetic)

        synthetic["iso"] = dict(media["iso"], sha256="0" * 64)
        with self.assertRaisesRegex(lab.LabSafetyError, "SHA256"):
            runner._validate_iso(pinned, synthetic)

        fake, fake_media = self.make_iso("synthetic-cd001.iso")
        fake_media["iso"]["size_bytes"] += 1
        fake_pin = runner._open_pinned(fake, writable=False, label="installation ISO")
        self.addCleanup(fake_pin.close)
        with self.assertRaisesRegex(lab.LabSafetyError, "size"):
            runner._validate_iso(fake_pin, fake_media)

        non_iso, non_iso_media = self.make_iso("no-structure.iso", cd001=False)
        non_iso_pin = runner._open_pinned(
            non_iso, writable=False, label="installation ISO"
        )
        self.addCleanup(non_iso_pin.close)
        with self.assertRaisesRegex(lab.LabSafetyError, "not an ISO-9660"):
            runner._validate_iso(non_iso_pin, non_iso_media)

    def test_profile_scenario_and_required_inputs_fail_closed(self) -> None:
        profile_path = self.root / "profile.json"
        schema_path = self.root / "profile.schema.json"
        profile_path.write_text(json.dumps({"profile_id": "profile-a"}))
        schema_path.write_text(
            json.dumps(
                {
                    "$defs": {
                        "only": {"const": {"profile_id": "profile-a", "changed": True}}
                    }
                }
            )
        )
        with (
            mock.patch.object(runner, "PROFILE_FILES", {"profile-a": profile_path}),
            mock.patch.object(runner, "PROFILE_SCHEMA", schema_path),
        ):
            with self.assertRaisesRegex(lab.LabSafetyError, "exact immutable"):
                runner._resolve_profile("profile-a", "scenario")

        with self.assertRaisesRegex(lab.LabSafetyError, "does not resolve exactly"):
            runner._resolve_profile(
                "windows-10-pro-22h2-en-us-x64-q35-11.0", "not-a-scenario"
            )

        profile = self.make_profile(
            {
                "id": "scenario",
                "secure_boot": "disabled",
                "tpm": "absent",
                "bitlocker": "disabled",
            }
        )
        with self.assertRaisesRegex(lab.LabSafetyError, "unresolved"):
            runner._resolve_required_inputs(profile, {})
        invalid = {
            item["id"]: hashlib.sha256(item["id"].encode()).hexdigest()
            for item in profile["required_inputs"]
        }
        invalid[next(iter(invalid))] = "not-a-digest"
        with self.assertRaisesRegex(lab.LabSafetyError, "not a resolved SHA256"):
            runner._resolve_required_inputs(profile, invalid)
        unresolved = dict(invalid)
        unresolved[next(iter(unresolved))] = "0" * 64
        with self.assertRaisesRegex(lab.LabSafetyError, "not a resolved SHA256"):
            runner._resolve_required_inputs(profile, unresolved)

        external_roles = {
            "ovmf-enrolled-vars": (
                "ovmf-enrolled-vars-sha256",
                self.root / "enrolled-vars.fd",
            ),
            "ovmf-fixed-vars": (
                "ovmf-fixed-vars-sha256",
                self.root / "fixed-vars.fd",
            ),
            "base-image-gpt": ("base-image-gpt-sha256", self.root / "gpt.bin"),
            "installer": ("installer-sha256", self.root / "installer.bin"),
            "installer-graph": (
                "installer-graph-sha256",
                self.root / "installer-graph.json",
            ),
            "release-manifest": (
                "release-manifest-sha256",
                self.root / "release-manifest.json",
            ),
            "boot-artifacts": (
                "boot-artifacts-sha256",
                self.root / "boot-artifacts.bin",
            ),
        }
        for input_id, path in external_roles.values():
            path.write_bytes(input_id.encode())
            invalid[input_id] = hashlib.sha256(path.read_bytes()).hexdigest()
        with self.assertRaisesRegex(lab.LabSafetyError, "missing"):
            runner._verify_external_input_files(profile, invalid, {})
        external_files = {role: value[1] for role, value in external_roles.items()}
        with self.assertRaisesRegex(lab.LabSafetyError, "canonical artifact role"):
            runner._verify_external_input_files(
                profile,
                invalid,
                {input_id: path for input_id, path in external_roles.values()},
            )
        for path in external_files.values():
            path.chmod(0o444)
        external_files["installer"].chmod(0o644)
        external_files["installer"].write_bytes(b"tampered")
        external_files["installer"].chmod(0o444)
        with self.assertRaisesRegex(lab.LabSafetyError, "does not match"):
            runner._verify_external_input_files(profile, invalid, external_files)

    def test_configuration_json_rejects_duplicate_keys_and_nonfinite_numbers(self) -> None:
        duplicate = self.root / "duplicate.json"
        duplicate.write_text('{"digest":"a","digest":"b"}', encoding="utf-8")
        with self.assertRaisesRegex(lab.LabSafetyError, "duplicate JSON object key"):
            runner._load_json(duplicate, "resolved profile inputs")

        nonfinite = self.root / "nonfinite.json"
        nonfinite.write_text('{"value":NaN}', encoding="utf-8")
        with self.assertRaisesRegex(lab.LabSafetyError, "non-finite JSON number"):
            runner._load_json(nonfinite, "profile input files")

    def test_version_and_base_virtual_size_constraints_fail_closed(self) -> None:
        executable = self.root / "qemu"
        executable.write_bytes(b"binary")
        constraint = {
            "minimum_inclusive": "11.0.0",
            "maximum_exclusive": "11.1.0",
        }
        with mock.patch.object(
            runner.subprocess,
            "run",
            return_value=mock.Mock(stdout="QEMU emulator version 11.0.3", stderr=""),
        ):
            runner._verify_version_constraint(executable, constraint, "QEMU", self.workspace)
        with mock.patch.object(
            runner.subprocess,
            "run",
            return_value=mock.Mock(stdout="QEMU emulator version 11.1.0", stderr=""),
        ):
            with self.assertRaisesRegex(lab.LabSafetyError, "outside"):
                runner._verify_version_constraint(
                    executable, constraint, "QEMU", self.workspace
                )

        base = self.workspace / "images" / "constraint-base.qcow2"
        base.write_bytes(b"base")
        base.chmod(0o444)
        resolved = {"base-image-sha256": hashlib.sha256(base.read_bytes()).hexdigest()}
        with mock.patch.object(
            runner,
            "_qcow2_info",
            return_value={"format": "qcow2", "virtual-size": 1024},
        ):
            with self.assertRaisesRegex(lab.LabSafetyError, "virtual size"):
                runner._validate_immutable_base(
                    base,
                    Path("qemu-img"),
                    2048,
                    resolved,
                    "base-image-sha256",
                )
        with mock.patch.object(
            runner,
            "_qcow2_info",
            return_value={
                "format": "qcow2",
                "virtual-size": 2048,
                "backing-filename": "hidden.qcow2",
            },
        ):
            with self.assertRaisesRegex(lab.LabSafetyError, "must not have a backing"):
                runner._validate_immutable_base(
                    base,
                    Path("qemu-img"),
                    2048,
                    resolved,
                    "base-image-sha256",
                )

    def test_run_ids_and_all_mutable_state_are_fresh_and_exclusive(self) -> None:
        first_id, first, evidence = runner._create_run_directory(self.workspace, "run-one")
        self.assertEqual(first_id, "run-one")
        self.assertTrue(first.is_dir())
        self.assertTrue(evidence.is_dir())
        with self.assertRaisesRegex(lab.LabSafetyError, "already exists"):
            runner._create_run_directory(self.workspace, "run-one")
        generated_id, generated, generated_evidence = runner._create_run_directory(
            self.workspace, None
        )
        self.assertNotEqual(generated_id, first_id)
        self.assertTrue(generated.is_dir())
        self.assertTrue(generated_evidence.is_dir())
        with self.assertRaisesRegex(lab.LabSafetyError, "invalid VM run ID"):
            runner._create_run_directory(self.workspace, "../escape")

    def test_standalone_writable_disk_and_hardlinked_overlay_are_rejected(self) -> None:
        standalone = self.workspace / "images" / "standalone.qcow2"
        standalone.write_bytes(b"qcow")
        with mock.patch.object(runner, "_qcow2_info", return_value={"format": "qcow2"}):
            with self.assertRaisesRegex(lab.LabSafetyError, "standalone writable"):
                runner.validate_and_pin_qcow2(
                    standalone, self.workspace, Path("qemu-img")
                )

        overlay = self.workspace / "images" / "overlay.qcow2"
        base = self.workspace / "images" / "base-read-only.qcow2"
        overlay.write_bytes(b"overlay")
        base.write_bytes(b"base")
        base.chmod(0o444)
        hardlink = overlay.with_name("overlay-hardlink.qcow2")

        def mutate_link_count(pinned, _qemu_img):
            if pinned.path == overlay:
                os.link(overlay, hardlink)
                return {"format": "qcow2", "backing-filename": str(base)}
            return {"format": "qcow2"}

        with mock.patch.object(runner, "_qcow2_info", side_effect=mutate_link_count):
            with self.assertRaisesRegex(lab.LabSafetyError, "hard-linked after pinning"):
                runner.validate_and_pin_qcow2(
                    overlay, self.workspace, Path("qemu-img"), require_backing=True
                )

        hardlink.unlink()
        hidden = self.workspace / "images" / "hidden.qcow2"
        hidden.write_bytes(b"hidden")
        hidden.chmod(0o444)
        with mock.patch.object(
            runner,
            "_qcow2_info",
            side_effect=[
                {"format": "qcow2", "backing-filename": str(base)},
                {"format": "qcow2", "backing-filename": str(hidden)},
                {"format": "qcow2"},
            ],
        ):
            with self.assertRaisesRegex(lab.LabSafetyError, "exactly one fresh overlay"):
                runner.validate_and_pin_qcow2(
                    overlay, self.workspace, Path("qemu-img"), require_backing=True
                )

    def test_qmp_audit_requires_exact_fdsets_and_node_graph(self) -> None:
        first = self.pin(self.workspace / "images" / "disk.qcow2")
        second = self.pin(self.root / "firmware.fd")
        first.fdset = 10
        second.fdset = 11
        nodes = {"disk-file-0", "disk-qcow-0"}
        query_block = [
            {
                "inserted": {
                    "file": (
                        'json:{"driver":"qcow2","file":{"driver":"file",'
                        '"filename":"/dev/fdset/10"}}'
                    ),
                    "backing_file": str(second.path),
                    "full-backing-filename": str(second.path),
                }
            }
        ]
        query_nodes = [
            {
                "node-name": "disk-file-0",
                "file": "/dev/fdset/10",
                "image": {
                    "filename": "json:{informational-open-options}",
                    "full-backing-filename": str(second.path),
                },
            },
            {
                "node-name": "disk-qcow-0",
                "file": (
                    'json:{"backing":{"driver":"file","filename":'
                    '"/dev/fdset/11"},"driver":"qcow2","file":'
                    '{"driver":"file","filename":"/dev/fdset/10"}}'
                ),
                "backing_file": "/dev/fdset/11",
            },
        ]
        evidence = runner.audit_qmp_block(query_block, query_nodes, [first, second], nodes)
        self.assertEqual(evidence["fdsets"], ["/dev/fdset/10", "/dev/fdset/11"])

        with self.assertRaisesRegex(lab.LabSafetyError, "omitted pinned fdsets"):
            runner.audit_qmp_block(query_block, query_nodes[:1], [first, second], {"disk-file-0"})
        unsafe_nodes = query_nodes + [{"node-name": "host", "file": "/dev/sda"}]
        with self.assertRaisesRegex(lab.LabSafetyError, "unapproved block backends"):
            runner.audit_qmp_block(query_block, unsafe_nodes, [first, second], nodes | {"host"})
        malformed_nodes = [dict(query_nodes[0], file="json:{not-json}")] + query_nodes[1:]
        with self.assertRaisesRegex(lab.LabSafetyError, "invalid serialized block"):
            runner.audit_qmp_block(query_block, malformed_nodes, [first, second], nodes)
        with self.assertRaisesRegex(lab.LabSafetyError, "block-node mismatch"):
            runner.audit_qmp_block(query_block, query_nodes, [first, second], nodes | {"extra"})

    def make_proc_fd(self, proc_root: Path, pid: int, number: int, target: str | Path) -> None:
        directory = proc_root / str(pid) / "fd"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / str(number)).symlink_to(str(target))

    def test_proc_audit_matches_exact_open_identities_and_rejects_other_workspace_files(self) -> None:
        pid = 4242
        proc_root = self.root / "proc"
        disk = self.pin(self.workspace / "images" / "disk.qcow2")
        firmware = self.pin(self.root / "firmware.fd")
        self.make_proc_fd(proc_root, pid, 0, "/dev/null")
        self.make_proc_fd(proc_root, pid, 3, disk.path)
        self.make_proc_fd(proc_root, pid, 4, firmware.path)
        self.make_proc_fd(proc_root, pid, 5, "socket:[123]")
        self.make_proc_fd(proc_root, pid, 7, "/memfd:displaysurface (deleted)")
        evidence = runner.audit_proc_fds(pid, [disk, firmware], proc_root)
        self.assertEqual(
            {item.get("label") for item in evidence if item["kind"] == "pinned-regular"},
            {disk.label, firmware.label},
        )
        self.assertIn("fixed-stdio", {item["kind"] for item in evidence})

        unpinned = self.workspace / "images" / "secret.txt"
        unpinned.write_text("secret")
        self.make_proc_fd(proc_root, pid, 6, unpinned)
        with self.assertRaisesRegex(lab.LabSafetyError, "unpinned regular file"):
            runner.audit_proc_fds(pid, [disk, firmware], proc_root)

        (proc_root / str(pid) / "fd" / "6").unlink()
        firmware.path.write_bytes(b"changed after validation")
        with self.assertRaisesRegex(lab.LabSafetyError, "changed after validation"):
            runner.audit_proc_fds(pid, [disk, firmware], proc_root)

    def test_proc_audit_rejects_devices_moved_pins_and_missing_pins(self) -> None:
        pid = 5252
        proc_root = self.root / "proc"
        disk = self.pin(self.workspace / "images" / "disk.qcow2", writable=True)
        self.make_proc_fd(proc_root, pid, 3, "/dev/null")
        with self.assertRaisesRegex(lab.LabSafetyError, "forbidden host device"):
            runner.audit_proc_fds(pid, [disk], proc_root)

        (proc_root / str(pid) / "fd" / "3").unlink()
        moved = disk.path.with_name("moved.qcow2")
        disk.path.rename(moved)
        self.make_proc_fd(proc_root, pid, 3, moved)
        with self.assertRaisesRegex(lab.LabSafetyError, "identity moved"):
            runner.audit_proc_fds(pid, [disk], proc_root)

        (proc_root / str(pid) / "fd" / "3").unlink()
        with self.assertRaisesRegex(lab.LabSafetyError, "did not retain"):
            runner.audit_proc_fds(pid, [disk], proc_root)

    def test_require_executable_rejects_setid_file(self) -> None:
        executable = self.root / "qemu"
        executable.write_bytes(b"binary")
        executable.chmod(0o4755)
        with mock.patch.object(runner.shutil, "which", return_value=str(executable)):
            with self.assertRaisesRegex(lab.LabSafetyError, "set-id"):
                runner._require_executable("qemu")

    def make_launch_plan(self) -> runner.LaunchPlan:
        disk = self.pin(
            self.workspace / "images" / "disk-overlay.qcow2", writable=True
        )
        disk.label = "VM disk"
        backing = self.pin(self.workspace / "images" / "base.qcow2")
        backing.path.chmod(0o444)
        backing.metadata = os.fstat(backing.descriptor)
        backing.label = "backing file"
        disk.fdset = 10
        backing.fdset = 11
        swtpm_socket = self.workspace / "runs" / "swtpm.sock"
        swtpm_socket.write_text("ready")
        return runner.LaunchPlan(
            self.workspace,
            ["/safe/qemu", "-S"],
            ["/safe/swtpm", "socket"],
            [disk, backing],
            [disk.path, backing.path],
            None,
            self.workspace / "runs" / "qmp.sock",
            swtpm_socket,
            {
                "qemu": {"path": "/safe/qemu"},
                "qemu_img": {"path": "/safe/qemu-img"},
                "swtpm": {"path": "/safe/swtpm"},
            },
            {"created": True},
            {"disk-file-0", "disk-qcow-0"},
        )

    def test_launch_audits_and_fsyncs_evidence_before_continuation(self) -> None:
        plan = self.make_launch_plan()
        events: list[str] = []

        class Process:
            def __init__(self, pid: int, code: int = 0):
                self.pid = pid
                self.code = code
                self.done = False
                self.terminated = False

            def poll(self):
                return self.code if self.done else None

            def wait(self, timeout=None):
                self.done = True
                return self.code

            def terminate(self):
                self.terminated = True
                self.done = True

            def kill(self):
                self.terminated = True
                self.done = True

        swtpm_process = Process(100)
        qemu_process = Process(200, 7)

        class QMP:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return None

            def execute(self, command):
                events.append(f"qmp:{command}")
                if command == "query-block":
                    return [{"inserted": {"file": "/dev/fdset/10"}}]
                if command == "query-named-block-nodes":
                    return []
                return {}

        def qmp_audit(*args):
            events.append("audit:qmp")
            return {"safe": True}

        def proc_audit(*args):
            events.append("audit:proc")
            return [{"safe": True}]

        def write_evidence(*args):
            events.append("evidence:fsynced")

        with (
            mock.patch.object(runner.os, "getuid", return_value=1000),
            mock.patch.object(runner.os, "geteuid", return_value=1000),
            mock.patch.object(runner.os, "getgid", return_value=1000),
            mock.patch.object(runner.os, "getegid", return_value=1000),
            mock.patch.object(runner, "_assert_executable_identity"),
            mock.patch.object(
                runner.subprocess, "Popen", side_effect=[swtpm_process, qemu_process]
            ) as popen,
            mock.patch.object(runner, "QMPClient", return_value=QMP()),
            mock.patch.object(runner, "audit_qmp_block", side_effect=qmp_audit),
            mock.patch.object(runner, "audit_proc_fds", side_effect=proc_audit),
            mock.patch.object(lab, "atomic_write_json", side_effect=write_evidence),
        ):
            self.assertEqual(runner.launch(plan), 7)
        self.assertLess(events.index("audit:qmp"), events.index("audit:proc"))
        self.assertLess(events.index("audit:proc"), events.index("evidence:fsynced"))
        self.assertLess(events.index("evidence:fsynced"), events.index("qmp:cont"))
        self.assertTrue(all(call.kwargs["start_new_session"] for call in popen.call_args_list))
        for call in popen.call_args_list:
            self.assertEqual(call.kwargs["cwd"], self.workspace / "runs" / "direct-qemu")
            self.assertEqual(
                set(call.kwargs["env"]), {"HOME", "LANG", "LC_ALL", "PATH", "TMPDIR"}
            )
            self.assertEqual(call.kwargs["stdin"], runner.subprocess.DEVNULL)
            self.assertEqual(call.kwargs["stdout"], runner.subprocess.DEVNULL)
            self.assertEqual(call.kwargs["stderr"], runner.subprocess.DEVNULL)
        self.assertEqual(
            popen.call_args_list[1].kwargs["pass_fds"],
            tuple(item.descriptor for item in plan.pins),
        )
        self.assertTrue(swtpm_process.terminated)

    def test_launch_tpm_absent_spawns_only_qemu(self) -> None:
        plan = self.make_launch_plan()
        plan.tpm_required = False
        plan.swtpm_socket = None
        plan.swtpm_argv = []
        plan.executable_facts.pop("swtpm")

        class Process:
            pid = 200

            def poll(self):
                return None

            def wait(self, timeout=None):
                return 0

            def terminate(self):
                return None

            def kill(self):
                return None

        class QMP:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return None

            def execute(self, command):
                if command == "query-block":
                    return [{"inserted": {"file": "/dev/fdset/10"}}]
                if command == "query-named-block-nodes":
                    return [{"node-name": "disk-file-0", "filename": "/dev/fdset/10"}]
                return {}

        with (
            mock.patch.object(runner.os, "getuid", return_value=1000),
            mock.patch.object(runner.os, "geteuid", return_value=1000),
            mock.patch.object(runner.os, "getgid", return_value=1000),
            mock.patch.object(runner.os, "getegid", return_value=1000),
            mock.patch.object(runner, "_assert_executable_identity"),
            mock.patch.object(runner.subprocess, "Popen", return_value=Process()) as popen,
            mock.patch.object(runner, "QMPClient", return_value=QMP()),
            mock.patch.object(runner, "audit_qmp_block", return_value={}),
            mock.patch.object(runner, "audit_proc_fds", return_value=[]),
            mock.patch.object(lab, "atomic_write_json"),
        ):
            self.assertEqual(runner.launch(plan), 0)
        self.assertEqual(popen.call_count, 1)

    def test_launch_fails_closed_before_cont_when_an_audit_fails(self) -> None:
        plan = self.make_launch_plan()
        commands: list[str] = []

        class Process:
            pid = 200

            def __init__(self):
                self.terminated = False

            def poll(self):
                return None if not self.terminated else 1

            def wait(self, timeout=None):
                return 1

            def terminate(self):
                self.terminated = True

            def kill(self):
                self.terminated = True

        processes = [Process(), Process()]

        class QMP:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return None

            def execute(self, command):
                commands.append(command)
                return [{}]

        with (
            mock.patch.object(runner.os, "getuid", return_value=1000),
            mock.patch.object(runner.os, "geteuid", return_value=1000),
            mock.patch.object(runner.os, "getgid", return_value=1000),
            mock.patch.object(runner.os, "getegid", return_value=1000),
            mock.patch.object(runner, "_assert_executable_identity"),
            mock.patch.object(runner.subprocess, "Popen", side_effect=processes),
            mock.patch.object(runner, "QMPClient", return_value=QMP()),
            mock.patch.object(
                runner, "audit_qmp_block", side_effect=lab.LabSafetyError("unsafe graph")
            ),
            mock.patch.object(lab, "atomic_write_json") as write_evidence,
        ):
            with self.assertRaisesRegex(lab.LabSafetyError, "unsafe graph"):
                runner.launch(plan)
        self.assertNotIn("cont", commands)
        write_evidence.assert_not_called()
        self.assertTrue(all(process.terminated for process in processes))

    def test_launch_rejects_root_and_setid_identities_without_spawning(self) -> None:
        plan = self.make_launch_plan()
        with (
            mock.patch.object(runner.os, "getuid", return_value=0),
            mock.patch.object(runner.os, "geteuid", return_value=0),
            mock.patch.object(runner.subprocess, "Popen") as popen,
        ):
            with self.assertRaisesRegex(lab.LabSafetyError, "as root"):
                runner.launch(plan)
            popen.assert_not_called()

        with (
            mock.patch.object(runner.os, "getuid", return_value=1000),
            mock.patch.object(runner.os, "geteuid", return_value=1001),
            mock.patch.object(runner.os, "getgid", return_value=1000),
            mock.patch.object(runner.os, "getegid", return_value=1000),
            mock.patch.object(runner.subprocess, "Popen") as popen,
        ):
            with self.assertRaisesRegex(lab.LabSafetyError, "set-id process"):
                runner.launch(plan)
            popen.assert_not_called()


if __name__ == "__main__":
    unittest.main()


class ControlMediaAttachmentTests(RunnerSafetyTests):
    """The control medium must widen the guest's inputs and nothing else.

    It is the only device added to a deliberately fixed topology, so the tests
    are about what it must *not* become: bootable, writable, or present when it
    was not asked for.
    """

    def control_image(self, name: str = "control.img") -> Path:
        image = self.workspace / name
        image.write_bytes(b"\0" * 4096)
        image.chmod(0o400)
        return image

    def test_a_launch_without_one_is_unchanged(self) -> None:
        """The sealed default must stay exactly as it was."""

        scenario = {
            "id": "secureboot-tpm-bitlocker-off",
            "secure_boot": "enabled",
            "tpm": "2.0",
            "bitlocker": "disabled",
        }
        plan = self.prepare_synthetic_plan(scenario, "no-control")
        self.addCleanup(plan.close)
        argv = " ".join(plan.qemu_argv)
        self.assertNotIn("control-media", argv)
        self.assertNotIn("control-media", plan.block_nodes)

    def test_the_medium_is_attached_read_only(self) -> None:
        scenario = {
            "id": "secureboot-tpm-bitlocker-off",
            "secure_boot": "enabled",
            "tpm": "2.0",
            "bitlocker": "disabled",
        }
        plan = self.prepare_synthetic_plan(
            scenario, "with-control", control_media=self.control_image()
        )
        self.addCleanup(plan.close)
        argv = " ".join(plan.qemu_argv)
        self.assertIn("drive=control-media", argv)
        # Both the file and raw nodes must declare read-only, or the guest could
        # rewrite the action it was handed. Parsed from the blockdev options
        # rather than matched as a substring, so the check does not depend on how
        # the JSON happens to be spaced.
        import json as _json

        nodes = {}
        for index, item in enumerate(plan.qemu_argv):
            if item != "-blockdev":
                continue
            option = _json.loads(plan.qemu_argv[index + 1])
            nodes[option["node-name"]] = option
        for name in ("control-media-file", "control-media"):
            with self.subTest(node=name):
                self.assertIn(name, nodes)
                self.assertIs(nodes[name].get("read-only"), True)
        for node in ("control-media-file", "control-media"):
            self.assertIn(node, plan.block_nodes)

    def test_the_medium_can_never_be_a_boot_source(self) -> None:
        """A bootable medium could change what the machine runs, not just what
        it is asked to do."""

        scenario = {
            "id": "secureboot-tpm-bitlocker-off",
            "secure_boot": "enabled",
            "tpm": "2.0",
            "bitlocker": "disabled",
        }
        plan = self.prepare_synthetic_plan(
            scenario, "no-boot", control_media=self.control_image()
        )
        self.addCleanup(plan.close)
        argv = " ".join(plan.qemu_argv)
        self.assertNotIn("drive=control-media,bootindex", argv)
        self.assertNotIn("bootindex=3", argv)

    def test_a_writable_medium_is_refused(self) -> None:
        """A writable input is one the guest could edit and re-present."""

        scenario = {
            "id": "secureboot-tpm-bitlocker-off",
            "secure_boot": "enabled",
            "tpm": "2.0",
            "bitlocker": "disabled",
        }
        writable = self.workspace / "writable-control.img"
        writable.write_bytes(b"\0" * 4096)
        writable.chmod(0o600)
        with self.assertRaises(lab.LabSafetyError) as raised:
            self.prepare_synthetic_plan(
                scenario, "writable-control", control_media=writable
            )
        self.assertIn("read-only", str(raised.exception))
