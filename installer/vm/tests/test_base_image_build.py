"""Tests for Windows base-image construction.

This module is the one place in the tree that cannot be proven by comparing
bytes, because its job is to make a real Windows installer run. So these tests
concentrate on the two things that *are* checkable without a 45-minute install:
that the QEMU command line cannot reach anything it should not, and that the
post-install inspection actually refuses a disk that is not a finished Windows
install.

The inspection tests build synthetic GPT disks rather than mocking, because the
failure being guarded against is "the checker silently inspects nothing", which a
mock would reproduce perfectly while proving nothing.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import base_image_build  # noqa: E402
import lab  # noqa: E402

PROFILE_KEY = "windows-11-enterprise-25h2-en-us-eval"

# ESP, MSR, Windows basic data: the roles a finished UEFI install must expose.
WINDOWS_LAYOUT = ("ef00", "0c01", "0700")


def have(*tools: str) -> bool:
    return all(shutil.which(tool) is not None for tool in tools)


def make_gpt_qcow2(destination: Path, type_codes: tuple[str, ...]) -> Path:
    """Build a synthetic qcow2 with the given GPT partition type codes."""

    raw = destination.with_suffix(".raw")
    subprocess.run(["truncate", "-s", "2G", str(raw)], check=True)
    arguments = ["sgdisk"]
    for index, code in enumerate(type_codes, start=1):
        size = "+100M" if index < len(type_codes) else "0"
        start = "2048" if index == 1 else "0"
        arguments += ["-n", f"{index}:{start}:{size}", "-t", f"{index}:{code}"]
    arguments.append(str(raw))
    subprocess.run(arguments, check=True, capture_output=True)
    subprocess.run(
        ["qemu-img", "convert", "-f", "raw", "-O", "qcow2", str(raw), str(destination)],
        check=True,
    )
    raw.unlink()
    return destination


class CommandLineSafetyTests(unittest.TestCase):
    """The build command line is reviewed statically; a VM is not needed."""

    def setUp(self) -> None:
        self.workspace = Path(tempfile.mkdtemp(prefix="bib-argv-"))
        self.addCleanup(shutil.rmtree, self.workspace, ignore_errors=True)
        self.inputs = base_image_build.BuildInputs(
            record_key=PROFILE_KEY,
            iso=self.workspace / "media.iso",
            answer_media=self.workspace / "answer.img",
            firmware_code=Path("/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd"),
            firmware_vars=self.workspace / "vars.fd",
            disk=self.workspace / "base.qcow2",
            virtual_size_bytes=137438953472,
        )

    @unittest.skipUnless(have("qemu-system-x86_64"), "qemu is unavailable")
    def argv(self) -> list[str]:
        return base_image_build.build_qemu_argv(self.inputs, self.workspace / "q.sock")

    @unittest.skipUnless(have("qemu-system-x86_64"), "qemu is unavailable")
    def test_the_guest_gets_no_network(self) -> None:
        """A base image must be a function of the ISO alone."""

        argv = self.argv()
        self.assertIn("none", argv[argv.index("-nic") + 1])
        joined = " ".join(argv)
        for forbidden in ("user,model=", "hostfwd", "tap,", "bridge"):
            with self.subTest(token=forbidden):
                self.assertNotIn(forbidden, joined)

    @unittest.skipUnless(have("qemu-system-x86_64"), "qemu is unavailable")
    def test_no_host_device_or_passthrough_is_reachable(self) -> None:
        joined = " ".join(self.argv())
        for forbidden in ("/dev/", "file=/dev", "iothread", "vfio", "usb-host", "virtfs"):
            with self.subTest(token=forbidden):
                self.assertNotIn(forbidden, joined)

    @unittest.skipUnless(have("qemu-system-x86_64"), "qemu is unavailable")
    def test_installation_media_is_attached_read_only(self) -> None:
        """The ISO and answer media are inputs and must not be writable."""

        argv = self.argv()
        for drive in [a for a in argv if a.startswith("if=none")]:
            if "install-iso" in drive or "answer" in drive:
                with self.subTest(drive=drive):
                    self.assertIn("readonly=on", drive)

    @unittest.skipUnless(have("qemu-system-x86_64"), "qemu is unavailable")
    def test_firmware_code_is_read_only_and_vars_are_a_copy(self) -> None:
        argv = self.argv()
        pflash = [a for a in argv if "if=pflash" in a]
        self.assertEqual(len(pflash), 2)
        code = next(a for a in pflash if "unit=0" in a)
        variables = next(a for a in pflash if "unit=1" in a)
        self.assertIn("readonly=on", code)
        # The writable store must be the per-build copy, never the enrolled
        # master and never the distribution template.
        self.assertNotIn("readonly=on", variables)
        self.assertIn(str(self.workspace), variables)

    @unittest.skipUnless(have("qemu-system-x86_64"), "qemu is unavailable")
    def test_secure_boot_requires_smm_and_the_secboot_firmware(self) -> None:
        argv = self.argv()
        machine = argv[argv.index("-machine") + 1]
        self.assertIn("smm=on", machine)
        code = next(a for a in argv if "if=pflash" in a and "unit=0" in a)
        self.assertIn("secboot", code)

    @unittest.skipUnless(have("qemu-system-x86_64"), "qemu is unavailable")
    def test_the_disk_matches_the_profile_storage_topology(self) -> None:
        """A base image is only valid for the topology the campaign will use."""

        profile = base_image_build.load_profile(PROFILE_KEY)
        joined = " ".join(self.argv())
        self.assertIn(profile["storage"]["serial"], joined)
        self.assertIn("nvme", joined)
        self.assertIn(
            f"logical_block_size={profile['storage']['logical_sector_bytes']}", joined
        )
        self.assertIn(
            f"physical_block_size={profile['storage']['physical_sector_bytes']}", joined
        )


class DiskCreationTests(unittest.TestCase):
    def setUp(self) -> None:
        scratch = lab.require_scratch_root()
        self.workspace = Path(tempfile.mkdtemp(prefix="bib-disk-", dir=scratch))
        os.chmod(self.workspace, 0o700)
        self.addCleanup(shutil.rmtree, self.workspace, ignore_errors=True)

    @unittest.skipUnless(have("qemu-img"), "qemu-img is unavailable")
    def test_a_disk_is_created_sparse_at_the_requested_size(self) -> None:
        disk = base_image_build.create_disk(self.workspace, "d.qcow2", 8 * 1024**3)
        self.assertTrue(disk.is_file())
        # qcow2 is sparse: the file on disk is far smaller than the virtual size.
        self.assertLess(os.stat(disk).st_size, 8 * 1024**3)

    @unittest.skipUnless(have("qemu-img"), "qemu-img is unavailable")
    def test_an_existing_disk_is_never_clobbered(self) -> None:
        base_image_build.create_disk(self.workspace, "d.qcow2", 8 * 1024**3)
        with self.assertRaises(base_image_build.BaseImageBuildError):
            base_image_build.create_disk(self.workspace, "d.qcow2", 8 * 1024**3)

    def test_a_nonpositive_size_is_refused(self) -> None:
        with self.assertRaises(base_image_build.BaseImageBuildError):
            base_image_build.create_disk(self.workspace, "z.qcow2", 0)


@unittest.skipUnless(
    have("guestfish", "qemu-img", "sgdisk", "truncate"),
    "guestfish, qemu-img, sgdisk or truncate is unavailable",
)
class InspectionTests(unittest.TestCase):
    """The central property: inspection must refuse a disk that is not an install."""

    def setUp(self) -> None:
        self.workspace = Path(tempfile.mkdtemp(prefix="bib-inspect-"))
        self.addCleanup(shutil.rmtree, self.workspace, ignore_errors=True)
        self.profile = base_image_build.load_profile(PROFILE_KEY)

    def inspect(self, type_codes: tuple[str, ...]):
        disk = make_gpt_qcow2(self.workspace / "d.qcow2", type_codes)
        return base_image_build.inspect_disk(disk, self.profile, self.workspace)

    def test_a_windows_like_layout_is_accepted(self) -> None:
        result = self.inspect(WINDOWS_LAYOUT)
        self.assertTrue(result["gpt_present"])
        self.assertEqual(result["partition_count"], 3)
        self.assertEqual(
            result["required_roles_present"], ["esp", "msr", "windows"]
        )

    def test_a_linux_layout_is_refused(self) -> None:
        """A GPT alone is not a Windows install."""

        with self.assertRaises(base_image_build.BaseImageBuildError) as caught:
            self.inspect(("8300",))
        self.assertIn("missing required partition roles", str(caught.exception))

    def test_a_disk_without_the_esp_is_refused(self) -> None:
        with self.assertRaises(base_image_build.BaseImageBuildError):
            self.inspect(("0c01", "0700"))

    def test_a_disk_without_the_windows_volume_is_refused(self) -> None:
        with self.assertRaises(base_image_build.BaseImageBuildError):
            self.inspect(("ef00", "0c01"))

    def test_an_unpartitioned_disk_is_refused(self) -> None:
        disk = self.workspace / "empty.qcow2"
        subprocess.run(
            ["qemu-img", "create", "-f", "qcow2", str(disk), "1G"],
            check=True,
            capture_output=True,
        )
        with self.assertRaises(base_image_build.BaseImageBuildError):
            base_image_build.inspect_disk(disk, self.profile, self.workspace)

    def test_the_gpt_digest_is_stable_and_layout_sensitive(self) -> None:
        """The pinned GPT digest must change when the table changes."""

        first = make_gpt_qcow2(self.workspace / "a.qcow2", WINDOWS_LAYOUT)
        digest_a = base_image_build.gpt_sha256(first, self.workspace)
        self.assertEqual(
            digest_a, base_image_build.gpt_sha256(first, self.workspace)
        )
        second = make_gpt_qcow2(self.workspace / "b.qcow2", ("8300",))
        self.assertNotEqual(
            digest_a, base_image_build.gpt_sha256(second, self.workspace)
        )

    def test_the_gpt_digest_leaves_no_temporary_behind(self) -> None:
        disk = make_gpt_qcow2(self.workspace / "c.qcow2", WINDOWS_LAYOUT)
        before = set(os.listdir(self.workspace))
        base_image_build.gpt_sha256(disk, self.workspace)
        self.assertEqual(set(os.listdir(self.workspace)), before)

    def test_inspection_does_not_use_sgdisk_on_the_qcow2(self) -> None:
        """sgdisk cannot read qcow2; using it would inspect nothing at all.

        This was a real defect during development: the first implementation used
        sgdisk and silently reported no partition table for a valid image.
        """

        import ast

        body = (ROOT / "base_image_build.py").read_text(encoding="utf-8")
        tree = ast.parse(body)
        function = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == "inspect_disk"
        )
        # Compare against the string literals the function actually executes,
        # parsed rather than grepped. The docstring names sgdisk precisely to
        # record why it is unsuitable, and that explanation must not trip the
        # check it explains.
        literals = {
            node.value
            for node in ast.walk(function)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        }
        literals.discard(ast.get_docstring(function))
        self.assertNotIn("sgdisk", literals)
        self.assertIn("guestfish", literals)


class BootPromptKeyTests(unittest.TestCase):
    """Keys must satisfy the boot prompt and then stop immediately.

    Regression coverage for a real defect: an earlier version sent Return on a
    fixed schedule, which kept typing into Windows setup's own UI after the
    prompt was gone, activated Cancel, and raised a quit confirmation over a 40%
    install. Disk growth is now the stopping signal.
    """

    def setUp(self) -> None:
        self.workspace = Path(tempfile.mkdtemp(prefix="bib-keys-"))
        self.addCleanup(shutil.rmtree, self.workspace, ignore_errors=True)
        self.disk = self.workspace / "d.qcow2"
        self.disk.write_bytes(b"\0" * 1024)

    class FakeMonitor:
        def __init__(self) -> None:
            self.sent = 0

        def send_key(self, key: str = "ret") -> None:
            self.sent += 1

    class FakeProcess:
        def __init__(self, alive: bool = True) -> None:
            self._alive = alive

        def poll(self):
            return None if self._alive else 0

    def test_keys_stop_once_the_guest_starts_writing(self) -> None:
        monitor = self.FakeMonitor()
        disk = self.disk

        original = os.stat

        calls = {"n": 0}

        def growing(path, *args, **kwargs):
            result = original(path, *args, **kwargs)
            if Path(path) == disk:
                calls["n"] += 1
                if calls["n"] > 2:
                    # Simulate setup writing the install image.
                    class Grown:
                        st_size = 1024 + 64 * 1024 * 1024

                    return Grown()
            return result

        with mock.patch.object(base_image_build.os, "stat", side_effect=growing):
            sent = base_image_build.press_boot_prompt_key(
                monitor, self.FakeProcess(), disk, attempts=20, interval=0
            )
        self.assertGreater(sent, 0, "the boot prompt must receive at least one key")
        self.assertLess(sent, 20, "keys must stop once the guest starts writing")

    def test_keys_stop_when_the_guest_exits(self) -> None:
        monitor = self.FakeMonitor()
        sent = base_image_build.press_boot_prompt_key(
            monitor, self.FakeProcess(alive=False), self.disk, attempts=20, interval=0
        )
        self.assertEqual(sent, 0)

    def test_the_attempt_budget_is_bounded(self) -> None:
        """Even with no disk growth, keys cannot be sent forever."""

        monitor = self.FakeMonitor()
        sent = base_image_build.press_boot_prompt_key(
            monitor, self.FakeProcess(), self.disk, attempts=5, interval=0
        )
        self.assertEqual(sent, 5)

    def test_a_closed_monitor_does_not_raise(self) -> None:
        class Broken:
            def send_key(self, key: str = "ret") -> None:
                raise OSError("monitor gone")

        sent = base_image_build.press_boot_prompt_key(
            Broken(), self.FakeProcess(), self.disk, attempts=5, interval=0
        )
        self.assertEqual(sent, 0)


class TpmTests(unittest.TestCase):
    """Windows 11 refuses to install without TPM 2.0."""

    def test_the_tpm_device_matches_the_profile(self) -> None:
        profile = base_image_build.load_profile(PROFILE_KEY)
        self.assertEqual(profile["security"]["tpm"]["version"], "2.0")
        argv = base_image_build.build_swtpm_argv(
            Path("/w/t.sock"), Path("/w/state")
        )
        self.assertIn("--tpm2", argv)
        self.assertIn("socket", argv)

    @unittest.skipUnless(have("qemu-system-x86_64"), "qemu is unavailable")
    def test_the_guest_is_given_the_profiles_tpm_model(self) -> None:
        profile = base_image_build.load_profile(PROFILE_KEY)
        inputs = base_image_build.BuildInputs(
            record_key=PROFILE_KEY,
            iso=Path("/w/a.iso"),
            answer_media=Path("/w/a.img"),
            firmware_code=Path("/f/c.fd"),
            firmware_vars=Path("/w/v.fd"),
            disk=Path("/w/d.qcow2"),
            virtual_size_bytes=1,
        )
        argv = base_image_build.build_qemu_argv(
            inputs, Path("/w/q.sock"), Path("/w/t.sock")
        )
        self.assertIn(profile["security"]["tpm"]["model"], " ".join(argv))

    @unittest.skipUnless(have("qemu-system-x86_64"), "qemu is unavailable")
    def test_the_usb_controller_precedes_the_device_that_needs_it(self) -> None:
        """Regression: QEMU refuses to start if usb-storage comes first."""

        inputs = base_image_build.BuildInputs(
            record_key=PROFILE_KEY,
            iso=Path("/w/a.iso"),
            answer_media=Path("/w/a.img"),
            firmware_code=Path("/f/c.fd"),
            firmware_vars=Path("/w/v.fd"),
            disk=Path("/w/d.qcow2"),
            virtual_size_bytes=1,
        )
        argv = base_image_build.build_qemu_argv(inputs, Path("/w/q.sock"))
        joined = " ".join(argv)
        self.assertLess(joined.index("qemu-xhci"), joined.index("usb-storage"))
        self.assertIn("bus=xhci.0", joined)


class StallDiagnosticTests(unittest.TestCase):
    """A stalled build must produce evidence, not just silence.

    Every defect in this build path so far was a modal dialog waiting for an
    answer nobody would give, and all of them looked identical from outside: a
    disk that stopped growing, followed by the full ninety-minute timeout. Three
    were identified by looking at the guest's screen. The watcher therefore
    captures it automatically, so the next one costs minutes rather than an hour.
    """

    def watcher(self) -> str:
        return (ROOT / "tools" / "watch_base_image_build.sh").read_text(encoding="utf-8")

    def test_the_watcher_captures_the_screen_on_a_sustained_stall(self) -> None:
        body = self.watcher()
        self.assertIn("capture_guest_screen.py", body)
        self.assertIn("STALL_POLLS", body)

    def test_the_capture_is_once_per_episode_not_once_per_poll(self) -> None:
        """A wall of identical screenshots is not more evidence than one."""

        self.assertIn("captured=1", self.watcher())

    def test_the_watcher_resolves_the_disk_through_the_media_record(self) -> None:
        """Guessing the name reported no-disk while the guest was 3 GiB in."""

        body = self.watcher()
        self.assertIn("record_id", body)
        self.assertIn("load_media_records", body)

    def test_the_capture_tool_never_sends_input(self) -> None:
        """A diagnostic that can perturb the run it diagnoses is a liability."""

        body = (ROOT / "tools" / "capture_guest_screen.py").read_text(encoding="utf-8")
        for forbidden in ("send-key", "human-monitor-command", "system_reset", "quit"):
            with self.subTest(command=forbidden):
                self.assertNotIn(f'"{forbidden}"', body)
        self.assertIn("screendump", body)


class EvidenceDocumentTests(unittest.TestCase):
    """The emitted document must satisfy the profile's own locators.

    The profile resolves its base-image-scoped inputs by JSON pointer into
    `base-image.json`. Nothing wrote that document, so those three inputs were
    unresolvable no matter how many images were built. The locators are read out
    of the profile here rather than restated, so a profile that adds or renames
    one fails this test instead of silently going unresolvable again.
    """

    def evidence(self) -> dict:
        return {
            "record_key": PROFILE_KEY,
            "sha256": "a" * 64,
            "gpt_sha256": "b" * 64,
            "inspection": {"gpt_present": True},
        }

    def test_every_base_image_scoped_locator_resolves(self) -> None:
        profile = base_image_build.load_profile(PROFILE_KEY)
        document = base_image_build.base_image_document(self.evidence(), "c" * 64)

        scoped = [
            item
            for item in profile["required_inputs"]
            if item.get("evidence_scope") == "base-image-acquisition"
        ]
        self.assertTrue(scoped, "the profile must declare base-image-scoped inputs")

        for item in scoped:
            with self.subTest(input_id=item["id"]):
                document_name, _, pointer = item["evidence_locator"].partition("#")
                self.assertEqual(document_name, "base-image.json")
                cursor = document
                for step in [part for part in pointer.split("/") if part]:
                    self.assertIn(step, cursor, f"{item['evidence_locator']} does not resolve")
                    cursor = cursor[step]
                self.assertRegex(
                    cursor, r"^[0-9a-f]{64}$", "a locator must resolve to a digest"
                )

    def test_the_digests_are_the_builds_own(self) -> None:
        """A document describing a different image would be worse than none."""

        document = base_image_build.base_image_document(self.evidence(), "c" * 64)
        self.assertEqual(document["image"]["sha256"], "a" * 64)
        self.assertEqual(document["disk"]["gpt_sha256"], "b" * 64)
        self.assertEqual(document["firmware"]["enrolled_vars_sha256"], "c" * 64)

    def test_the_whole_build_evidence_is_retained(self) -> None:
        document = base_image_build.base_image_document(self.evidence(), "c" * 64)
        self.assertEqual(document["guest"]["build"]["record_key"], PROFILE_KEY)

    def test_the_build_writes_the_document_it_promises(self) -> None:
        body = (ROOT / "base_image_build.py").read_text(encoding="utf-8")
        builder = body[body.index("def build(") :]
        self.assertIn('workspace / "base-image.json"', builder)
        self.assertLess(
            builder.index("inspect_disk("),
            builder.index("base_image_document("),
            "evidence must only be emitted for a disk that passed inspection",
        )


class TerminationTests(unittest.TestCase):
    """A signalled guest must be reported as signalled.

    Regression coverage for a real defect: earlyoom reclaimed a Windows 11
    install at roughly 40%, QEMU handled SIGTERM and exited *zero*, and the
    build inspected the half-written disk and reported
    `parted: unrecognised disk label`. That message was true and useless: it
    described the symptom on the disk and named nothing about the cause.
    """

    def test_a_sigterm_notice_is_recognised(self) -> None:
        observed = base_image_build.termination_signal(
            "qemu-system-x86_64: terminating on signal 15 from pid 923 "
            "(/usr/bin/earlyoom)"
        )
        self.assertEqual(observed, (15, 923))

    def test_a_signal_without_a_named_killer_is_still_recognised(self) -> None:
        observed = base_image_build.termination_signal(
            "qemu-system-x86_64: terminating on signal 15"
        )
        self.assertEqual(observed, (15, None))

    def test_an_ordinary_log_is_not_mistaken_for_a_kill(self) -> None:
        """A build that really finished must not be failed by this check."""

        for benign in ("", "warning: TCG doesn't support requested feature\n"):
            with self.subTest(log=benign):
                self.assertIsNone(base_image_build.termination_signal(benign))

    def test_the_build_consults_the_log_before_trusting_the_disk(self) -> None:
        """The check must precede inspection, or it cannot prevent the misreport."""

        body = (ROOT / "base_image_build.py").read_text(encoding="utf-8")
        builder = body[body.index("def build(") :]
        self.assertLess(
            builder.index("termination_signal("),
            builder.index("inspect_disk("),
            "a signalled guest must be caught before its disk is inspected",
        )


class MemoryEnvelopeTests(unittest.TestCase):
    """An unresumable 45-minute install must not start into an OOM."""

    def test_a_starved_host_is_refused(self) -> None:
        with mock.patch.object(
            base_image_build.lab, "available_memory_bytes", return_value=512 * 1024**2
        ):
            with self.assertRaises(base_image_build.BaseImageBuildError) as raised:
                base_image_build.require_memory_envelope()
        self.assertIn("536870912", str(raised.exception))

    def test_a_healthy_host_is_allowed_and_the_figure_is_returned(self) -> None:
        plenty = 64 * 1024**3
        with mock.patch.object(
            base_image_build.lab, "available_memory_bytes", return_value=plenty
        ):
            self.assertEqual(base_image_build.require_memory_envelope(), plenty)

    def test_the_floor_exceeds_the_guest_envelope(self) -> None:
        """A floor equal to the guest size would leave the host nothing."""

        guest = base_image_build.MEMORY_MIB * 1024**2
        floor = guest + base_image_build.HOST_MEMORY_RESERVE_BYTES
        with mock.patch.object(
            base_image_build.lab, "available_memory_bytes", return_value=guest
        ):
            with self.assertRaises(base_image_build.BaseImageBuildError):
                base_image_build.require_memory_envelope(floor)

    def test_the_build_checks_memory_before_launching_anything(self) -> None:
        body = (ROOT / "base_image_build.py").read_text(encoding="utf-8")
        builder = body[body.index("def build(") :]
        self.assertLess(
            builder.index("require_memory_envelope("),
            builder.index("subprocess.Popen("),
            "the envelope must be checked before a process is started",
        )


class StaticSafetyTests(unittest.TestCase):
    def test_the_module_names_no_privileged_or_device_primitive(self) -> None:
        body = (ROOT / "base_image_build.py").read_text(encoding="utf-8")
        for forbidden in ("losetup", "partprobe", "kpartx", "sudo", "mount(", "libvirt"):
            with self.subTest(token=forbidden):
                self.assertNotIn(forbidden, body)

    def test_a_timeout_is_a_failure_not_a_success(self) -> None:
        """A stalled installer must never be recorded as a completed build."""

        body = (ROOT / "base_image_build.py").read_text(encoding="utf-8")
        waiter = body[body.index("def wait_for_shutdown") : body.index("def prepare_inputs")]
        self.assertIn("raise BaseImageBuildError", waiter)
        self.assertIn("did not power off", waiter)

    def test_a_nonzero_qemu_exit_is_a_failure(self) -> None:
        body = (ROOT / "base_image_build.py").read_text(encoding="utf-8")
        self.assertIn("QEMU exited {exit_code}", body)

    def test_a_failed_build_reports_qemus_own_diagnostics(self) -> None:
        """An exit code alone is not actionable.

        The first real failure here was QEMU refusing to start because a USB
        device preceded its controller, and the error said only "exited 1".
        """

        body = (ROOT / "base_image_build.py").read_text(encoding="utf-8")
        self.assertIn("diagnostics_text[-600:]", body)
        self.assertIn("no diagnostics were produced", body)

    def test_building_as_root_is_refused(self) -> None:
        body = (ROOT / "base_image_build.py").read_text(encoding="utf-8")
        self.assertIn("refusing to build a base image as root", body)


if __name__ == "__main__":
    unittest.main()
