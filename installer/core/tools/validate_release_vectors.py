#!/usr/bin/env python3
"""Independently verify the Rust-generated release signature known-answer vector."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
DOMAIN = b"JSTACK-RELEASE-MANIFEST-V1\0"
EXPECTED_DIGEST = "17d3a22dcf9973f9cb35a628d598deeee76449377e5718c976a5362f7f832fa1"
EXPECTED_SIGNATURES = {
    "34750f98bd59fcfc946da45aaabe933be154a4b5094e1c4abf42866505f3c97e": "fa3f03264215a2bdea7d73cafd4e9deebdf63d57c37b7eae05c5e5d085eb0212229e4d585ad190f928854f210739e231099db64e019b0f468f49713e864d330b",
    "6a3803d5f059902a1c6dafbc9ba4729212f7caac08634cc3ae76b27529f03827": "5a1e0769b548d4b4585508749a9a80dab9a7d0bae90f97b2456f0d6941fbb8bcf8f39a1d6238209f19c686fbf55ee350aa88f2e701bc545bf0b4b7f70b86330a",
}
ARTIFACT_BYTES = {
    "esp_loader": b"jstack-esp-loader-fixture\n",
    "installer_uki": b"jstack-installer-uki-fixture\n",
    "offline_system_image": b"jstack-offline-system-image-fixture\n",
    "recovery_uki": b"jstack-recovery-uki-fixture\n",
}


def canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> int:
    manifest_path = ROOT / "fixtures" / "signed-release-manifest.json"
    acceptance_path = ROOT / "fixtures" / "release-acceptance-state.json"
    raw = manifest_path.read_bytes()
    envelope = json.loads(raw)
    if canonical(envelope) != raw:
        fail("signed release fixture is not byte-canonical JSON")

    body = canonical(envelope["signed"])
    message = DOMAIN + len(body).to_bytes(8, "big") + body
    digest = hashlib.sha256(message).hexdigest()
    if digest != EXPECTED_DIGEST:
        fail(f"release message digest changed: {digest}")

    observed = {item["key_id"]: item["signature_hex"] for item in envelope["signatures"]}
    if observed != EXPECTED_SIGNATURES:
        fail("release Ed25519 signature known-answer vector changed")
    if list(observed) != sorted(observed):
        fail("release signatures are not sorted by distinct key id")

    for seed_byte in (1, 2):
        private = Ed25519PrivateKey.from_private_bytes(bytes([seed_byte]) * 32)
        public = private.public_key()
        public_bytes = public.public_bytes_raw()
        key_id = hashlib.sha256(public_bytes).hexdigest()
        signature = bytes.fromhex(observed[key_id])
        public.verify(signature, message)
        try:
            public.verify(signature, message + b"\0")
        except InvalidSignature:
            pass
        else:
            fail("Ed25519 signature accepted a changed domain message")

    acceptance = json.loads(acceptance_path.read_bytes())
    if acceptance["manifest_digest"] != digest:
        fail("durable acceptance fixture is not bound to the signed body digest")
    if acceptance["highest_sequence"] != envelope["signed"]["release_sequence"]:
        fail("durable acceptance fixture is not bound to the release sequence")
    if acceptance["channel"] != envelope["signed"]["channel"]:
        fail("durable acceptance fixture is not bound to the release channel")
    if acceptance["state_model_sha256"] != envelope["signed"]["state_model_sha256"]:
        fail("durable acceptance fixture is not bound to the state-model digest")

    roles = [artifact["role"] for artifact in envelope["signed"]["artifacts"]]
    if roles != list(ARTIFACT_BYTES):
        fail("artifact roles are not the closed sorted v1 set")
    for artifact in envelope["signed"]["artifacts"]:
        payload = ARTIFACT_BYTES[artifact["role"]]
        chunk_size = artifact["chunk_size_bytes"]
        chunks = [payload[index : index + chunk_size] for index in range(0, len(payload), chunk_size)]
        if artifact["size_bytes"] != len(payload):
            fail(f"{artifact['role']} size vector changed")
        if artifact["sha256"] != hashlib.sha256(payload).hexdigest():
            fail(f"{artifact['role']} whole digest vector changed")
        if artifact["chunk_sha256"] != [hashlib.sha256(chunk).hexdigest() for chunk in chunks]:
            fail(f"{artifact['role']} logical chunk vector changed")

    print("validated independent canonical Ed25519 and artifact known-answer vectors")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
