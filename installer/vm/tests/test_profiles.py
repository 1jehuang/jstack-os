from __future__ import annotations

import copy
import hashlib
import json
import unittest
from pathlib import Path
from urllib.parse import urlparse

from jsonschema import Draft202012Validator


PROFILES = Path(__file__).resolve().parents[1] / "profiles"
MEDIA_SCHEMA_PATH = PROFILES / "media.schema.json"
PROFILE_SCHEMA_PATH = PROFILES / "profile.schema.json"
MEDIA_PATHS = {
    "windows-11-enterprise-25h2-eval-en-us-x64": (
        PROFILES / "windows-11-enterprise-25h2-en-us-eval.media.json"
    ),
    "windows-10-pro-22h2-en-us-x64": (
        PROFILES / "windows-10-pro-22h2-en-us.media.json"
    ),
}
PROFILE_PATHS = {
    "windows-11-enterprise-25h2-eval-en-us-x64-q35-11.0": (
        PROFILES / "windows-11-enterprise-25h2-en-us-eval.profile.json"
    ),
    "windows-10-pro-22h2-en-us-x64-q35-11.0": (
        PROFILES / "windows-10-pro-22h2-en-us.profile.json"
    ),
}


def load(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def set_path(value: dict[str, object], path: tuple[object, ...], replacement: object) -> None:
    target: object = value
    for component in path[:-1]:
        if isinstance(component, int):
            assert isinstance(target, list)
            target = target[component]
        else:
            assert isinstance(target, dict)
            target = target[component]
    final = path[-1]
    if isinstance(final, int):
        assert isinstance(target, list)
        target[final] = replacement
    else:
        assert isinstance(target, dict)
        target[final] = replacement


def scalar_paths(value: object, path: tuple[object, ...] = ()) -> list[tuple[object, ...]]:
    if isinstance(value, dict):
        return [
            child_path
            for key, child in value.items()
            for child_path in scalar_paths(child, (*path, key))
        ]
    if isinstance(value, list):
        return [
            child_path
            for index, child in enumerate(value)
            for child_path in scalar_paths(child, (*path, index))
        ]
    return [path]


def changed_scalar(value: object) -> object:
    if value is None:
        return "invented-value"
    if isinstance(value, bool):
        return not value
    if isinstance(value, int):
        return value + 1
    if isinstance(value, str):
        return f"{value}-mutated"
    raise AssertionError(f"unsupported scalar type: {type(value).__name__}")


class ProfileRecordTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.media_schema = load(MEDIA_SCHEMA_PATH)
        cls.profile_schema = load(PROFILE_SCHEMA_PATH)
        cls.media_validator = Draft202012Validator(cls.media_schema)
        cls.profile_validator = Draft202012Validator(cls.profile_schema)
        cls.media = {record_id: load(path) for record_id, path in MEDIA_PATHS.items()}
        cls.profiles = {
            profile_id: load(path) for profile_id, path in PROFILE_PATHS.items()
        }

    def test_schemas_are_valid_draft_2020_12(self) -> None:
        Draft202012Validator.check_schema(self.media_schema)
        Draft202012Validator.check_schema(self.profile_schema)

    def test_all_media_and_profile_records_validate(self) -> None:
        for record_id, record in self.media.items():
            with self.subTest(record_id=record_id):
                self.media_validator.validate(record)
                self.assertEqual(record["record_id"], record_id)
        for profile_id, profile in self.profiles.items():
            with self.subTest(profile_id=profile_id):
                self.profile_validator.validate(profile)
                self.assertEqual(profile["profile_id"], profile_id)

    def test_exact_media_contracts(self) -> None:
        win11 = self.media["windows-11-enterprise-25h2-eval-en-us-x64"]
        self.assertEqual(
            win11["iso"],
            {
                "filename": "windows-11-enterprise-25h2-eval-en-us-x64.iso",
                "size_bytes": 7092807680,
                "sha256": "a61adeab895ef5a4db436e0a7011c92a2ff17bb0357f58b13bbc4062e535e7b9",
            },
        )
        self.assertEqual(
            win11["acquisition"]["source_page_url"],
            "https://www.microsoft.com/en-us/evalcenter/download-windows-11-enterprise",
        )
        self.assertEqual(
            win11["authentication"]["publication"]["source_url"],
            "https://go.microsoft.com/fwlink/?linkid=2334901",
        )
        self.assertEqual(
            win11["authentication"]["published_iso_sha256"],
            win11["iso"]["sha256"],
        )
        self.assertEqual(win11["product"]["architecture"], "x86_64")
        self.assertEqual(win11["product"]["language"], "en-US")
        self.assertEqual(
            win11["authentication"]["publication"]["sha256"],
            "0d44bc561af90844c0a0da5ddc420f5fa84459872c02a1def6240fcfe1aac2c7",
        )
        self.assertEqual(
            win11["install_image"],
            {
                "path": "sources/install.wim",
                "size_bytes": 6225286811,
                "sha256": "119100d92fa9516d47c9933f9c6f4e2b1940bd685762fdca6982e6d29b353985",
                "image_count": 1,
                "selected_index": 1,
                "selected_name": "Windows 11 Enterprise Evaluation",
                "architecture": "x86_64",
                "language": "en-US",
                "version": {
                    "major": 10,
                    "minor": 0,
                    "build": 26200,
                    "service_pack_build": 6584,
                },
            },
        )

        win10 = self.media["windows-10-pro-22h2-en-us-x64"]
        self.assertEqual(win10["product"]["edition"], "Pro")
        self.assertEqual(win10["product"]["release"], "22H2")
        self.assertEqual(win10["product"]["architecture"], "x86_64")
        self.assertEqual(win10["product"]["language"], "en-US")
        self.assertEqual(
            win10["iso"],
            {
                "filename": "Win10_22H2_English_x64v1.iso",
                "size_bytes": 6140975104,
                "sha256": "a6f470ca6d331eb353b815c043e327a347f594f37ff525f17764738fe812852e",
            },
        )
        self.assertEqual(
            win10["acquisition"]["source_page_url"],
            "https://www.microsoft.com/en-us/software-download/windows10ISO",
        )
        self.assertEqual(win10["acquisition"]["product_edition_id"], 2618)
        self.assertEqual(win10["acquisition"]["language_selection"], "English")
        self.assertEqual(win10["acquisition"]["architecture_selection"], "x64")
        self.assertEqual(win10["acquisition"]["sku_id"], 16067)
        self.assertEqual(
            win10["authentication"]["published_iso_sha256"],
            win10["iso"]["sha256"],
        )
        self.assertEqual(win10["install_image"]["selected_index"], 6)
        self.assertEqual(win10["install_image"]["selected_name"], "Windows 10 Pro")
        self.assertEqual(win10["install_image"]["image_count"], 11)
        self.assertEqual(win10["install_image"]["version"]["build"], 19041)
        self.assertEqual(
            win10["install_image"]["sha256"],
            "e86cfd152ecf337d53d3222558234d52e95abfdf0e2414c45c4a3b5069ea7cc5",
        )

    def test_only_stable_source_pages_are_persisted(self) -> None:
        allowed_urls = {
            "https://www.microsoft.com/en-us/evalcenter/download-windows-11-enterprise",
            "https://go.microsoft.com/fwlink/?linkid=2334901",
            "https://www.microsoft.com/en-us/software-download/windows10ISO",
        }
        for record_id, record in self.media.items():
            serialized = json.dumps(record)
            self.assertNotIn("software-static.download", serialized)
            self.assertNotIn("download.prss.microsoft.com", serialized)
            self.assertEqual(
                record["acquisition"]["resolved_download_url_retention"], "forbidden"
            )
            urls: list[str] = []

            def collect(value: object) -> None:
                if isinstance(value, dict):
                    for key, child in value.items():
                        if key.endswith("url"):
                            self.assertIsInstance(child, str)
                            urls.append(child)
                        collect(child)
                elif isinstance(value, list):
                    for child in value:
                        collect(child)

            collect(record)
            with self.subTest(record_id=record_id):
                self.assertTrue(urls)
                self.assertLessEqual(set(urls), allowed_urls)
                for url in urls:
                    parsed = urlparse(url)
                    self.assertEqual(parsed.scheme, "https")
                    self.assertIn(
                        parsed.hostname,
                        {"www.microsoft.com", "go.microsoft.com"},
                    )

    def test_profiles_pin_platform_and_reference_exact_media_bytes(self) -> None:
        for profile_id, profile in self.profiles.items():
            with self.subTest(profile_id=profile_id):
                self.assertEqual(profile["status"], "blocked-required-inputs")
                self.assertEqual(
                    profile["qemu"]["version_constraint"],
                    {
                        "minimum_inclusive": "11.0.0",
                        "maximum_exclusive": "11.1.0",
                    },
                )
                self.assertEqual(profile["qemu"]["machine"]["type"], "pc-q35-11.0")
                self.assertTrue(profile["qemu"]["machine"]["smm"])
                self.assertEqual(profile["firmware"]["implementation"], "OVMF")
                self.assertEqual(
                    profile["firmware"]["code"]["sha256_input"],
                    "ovmf-code-sha256",
                )
                self.assertEqual(
                    profile["firmware"]["nonsecure_code"],
                    {
                        "canonical_name": "OVMF_CODE.4m.fd",
                        "mode": "read-only",
                        "sha256_input": "ovmf-nonsecure-code-sha256",
                        "digest_evidence_scope": "host-acquisition",
                    },
                )
                self.assertEqual(
                    profile["firmware"]["enrolled_vars"]["sha256_input"],
                    "ovmf-enrolled-vars-sha256",
                )
                self.assertEqual(
                    profile["firmware"]["fixed_vars"],
                    {
                        "canonical_name": "OVMF_VARS.4m.fd",
                        "enrollment": "none",
                        "copy_policy": "immutable-master-per-run-copy",
                        "sha256_input": "ovmf-fixed-vars-sha256",
                        "digest_evidence_scope": "host-acquisition",
                    },
                )
                self.assertEqual(
                    profile["security"]["secure_boot"]["variants"],
                    ["enabled", "disabled"],
                )
                self.assertEqual(profile["security"]["tpm"]["version"], "2.0")
                self.assertEqual(
                    profile["security"]["bitlocker"]["variants"],
                    ["disabled", "enabled"],
                )
                self.assertEqual(profile["storage"]["controller"], "nvme")
                self.assertEqual(profile["storage"]["serial"], "JSTACKLAB0001")
                self.assertEqual(profile["storage"]["logical_sector_bytes"], 512)
                self.assertEqual(profile["storage"]["physical_sector_bytes"], 4096)
                self.assertEqual(
                    profile["network"],
                    {
                        "controller": "e1000e",
                        "backend": "user",
                        "mac_address": "52:54:00:4a:53:01",
                        "host_forwarding": "disabled",
                        "inbox_windows_driver": True,
                    },
                )
                self.assertEqual(profile["compute"]["ram_bytes"], 4294967296)
                self.assertEqual(profile["compute"]["cpu"]["vcpus"], 4)
                self.assertEqual(
                    profile["storage"]["layout"]["ordered_partition_roles"],
                    ["esp", "msr", "windows", "recovery"],
                )

                record_path = PROFILES.parent / profile["media"]["record_path"]
                self.assertTrue(record_path.is_file())
                self.assertEqual(
                    hashlib.sha256(record_path.read_bytes()).hexdigest(),
                    profile["media"]["record_sha256"],
                )

    def test_required_hashes_are_explicitly_unresolved(self) -> None:
        required_ids = {
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
        for profile_id, profile in self.profiles.items():
            inputs = {item["id"]: item for item in profile["required_inputs"]}
            with self.subTest(profile_id=profile_id):
                self.assertEqual(set(inputs), required_ids)
                for item in inputs.values():
                    self.assertEqual(item["type"], "sha256")
                    self.assertEqual(item["state"], "required-unresolved")
                    self.assertIsNone(item["value"])
                    self.assertTrue(item["evidence_scope"])
                    self.assertTrue(item["evidence_locator"])
                self.assertEqual(
                    profile["artifacts"],
                    {
                        "installer_sha256_input": "installer-sha256",
                        "installer_graph_sha256_input": "installer-graph-sha256",
                        "release_manifest_sha256_input": "release-manifest-sha256",
                        "boot_artifacts_sha256_input": "boot-artifacts-sha256",
                    },
                )

    def test_stale_windows_10_enterprise_requirement_is_gone(self) -> None:
        self.assertFalse(
            (PROFILES / "windows-10-enterprise-en-us.required.media.json").exists()
        )
        win10 = self.media["windows-10-pro-22h2-en-us-x64"]
        self.assertEqual(win10["availability"], "available")
        self.assertNotEqual(win10["product"]["edition"], "Enterprise Evaluation")

    def test_media_identity_and_provenance_mutations_are_rejected(self) -> None:
        cases = [
            (
                "windows-11-enterprise-25h2-eval-en-us-x64",
                ("iso", "filename"),
                "renamed.iso",
            ),
            (
                "windows-11-enterprise-25h2-eval-en-us-x64",
                ("iso", "size_bytes"),
                7092807681,
            ),
            (
                "windows-11-enterprise-25h2-eval-en-us-x64",
                ("iso", "sha256"),
                "0" * 64,
            ),
            (
                "windows-11-enterprise-25h2-eval-en-us-x64",
                ("acquisition", "source_page_url"),
                "https://example.invalid/windows.iso",
            ),
            (
                "windows-11-enterprise-25h2-eval-en-us-x64",
                ("authentication", "publication", "sha256"),
                "0" * 64,
            ),
            (
                "windows-11-enterprise-25h2-eval-en-us-x64",
                ("install_image", "selected_index"),
                2,
            ),
            (
                "windows-10-pro-22h2-en-us-x64",
                ("product", "edition"),
                "Enterprise",
            ),
            (
                "windows-10-pro-22h2-en-us-x64",
                ("acquisition", "product_edition_id"),
                0,
            ),
            (
                "windows-10-pro-22h2-en-us-x64",
                ("acquisition", "sku_id"),
                0,
            ),
            (
                "windows-10-pro-22h2-en-us-x64",
                ("authentication", "published_iso_sha256"),
                "f" * 64,
            ),
            (
                "windows-10-pro-22h2-en-us-x64",
                ("install_image", "selected_name"),
                "Windows 10 Home",
            ),
        ]
        for record_id, path, replacement in cases:
            mutated = copy.deepcopy(self.media[record_id])
            set_path(mutated, path, replacement)
            with self.subTest(record_id=record_id, path=path):
                self.assertFalse(self.media_validator.is_valid(mutated))

    def test_profile_platform_and_required_input_mutations_are_rejected(self) -> None:
        cases = [
            (("status",), "supported"),
            (("qemu", "version_constraint", "minimum_inclusive"), "11.0.1"),
            (("qemu", "machine", "type"), "pc-q35-10.0"),
            (("firmware", "code", "sha256_input"), "made-up-sha256"),
            (("firmware", "enrolled_vars", "enrollment"), "none"),
            (("security", "secure_boot", "variants", 0), "disabled"),
            (("security", "tpm", "model"), "tpm-tis"),
            (("security", "bitlocker", "enabled_encryption_method"), "none"),
            (("storage", "controller"), "virtio-blk-pci"),
            (("storage", "serial"), "OTHERDISK"),
            (("storage", "logical_sector_bytes"), 4096),
            (("storage", "layout", "partition_table"), "mbr"),
            (("network", "controller"), "virtio-net-pci"),
            (("network", "mac_address"), "52:54:00:00:00:00"),
            (("compute", "ram_bytes"), 2147483648),
            (("compute", "cpu", "vcpus"), 2),
            (("artifacts", "installer_graph_sha256_input"), "graph-placeholder"),
            (("required_inputs", 1, "value"), "0" * 64),
        ]
        for profile_id, profile in self.profiles.items():
            for path, replacement in cases:
                mutated = copy.deepcopy(profile)
                set_path(mutated, path, replacement)
                with self.subTest(profile_id=profile_id, path=path):
                    self.assertFalse(self.profile_validator.is_valid(mutated))

        mutated = copy.deepcopy(
            self.profiles["windows-10-pro-22h2-en-us-x64-q35-11.0"]
        )
        mutated["security"]["tpm"]["absent_variant_permitted"] = False
        self.assertFalse(self.profile_validator.is_valid(mutated))

    def test_every_scalar_and_unexpected_field_mutation_is_rejected(self) -> None:
        collections = (
            ("media", self.media, self.media_validator),
            ("profile", self.profiles, self.profile_validator),
        )
        for kind, records, validator in collections:
            for record_id, record in records.items():
                for path in scalar_paths(record):
                    mutated = copy.deepcopy(record)
                    target: object = record
                    for component in path:
                        target = target[component]
                    set_path(mutated, path, changed_scalar(target))
                    with self.subTest(kind=kind, record_id=record_id, path=path):
                        self.assertFalse(validator.is_valid(mutated))

                mutated = copy.deepcopy(record)
                mutated["unexpected"] = True
                with self.subTest(kind=kind, record_id=record_id, path="unexpected"):
                    self.assertFalse(validator.is_valid(mutated))


if __name__ == "__main__":
    unittest.main()
