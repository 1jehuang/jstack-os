# Milestone 3 review

## Result

Milestone 3 adds a Windows-only live storage observer and a cross-platform,
side-effect-free normalizer. `jstack-inventory.exe` invokes one embedded
PowerShell script, parses the strict `WindowsStorageSnapshot` contract, and emits
the shared `Inventory` contract. The shared library still forbids unsafe Rust.
The Windows launcher has one documented, locally allowed native system-directory
query, and live collection is unavailable on non-Windows targets.

No storage mutation is implemented or linked.

## Safety findings resolved during implementation

1. Raw observation initially risked being confused with authorization. Secure
   Boot enablement now remains `enabled_untrusted`, BitLocker recovery-material
   confirmation remains false, and firmware-variable writability remains false.
   A regression test proves observed inventory cannot authorize planning.
2. Additional Microsoft Basic Data partitions could have been mistaken for the
   Windows system volume. Selection now requires the `%SystemDrive%` letter and
   Windows `IsBoot` evidence with exactly one match across all disks. A valid
   two-disk ambiguity counterexample is rejected. The one active `IsSystem` ESP
   must also reside on that selected disk, so split firmware/Windows boot disks
   fail closed.
3. Existing JStack XBOOTLDR and x86-64 root type GUIDs initially would have been
   classified as generic partitions. GPT type constants now have one shared
   source, and the adapter emits the explicit JStack roles so the v1 planner
   rejects reinstall or resume layouts rather than treating them as unrelated.
4. Schema-only constraints could have been bypassed by direct Rust JSON parsing.
   Raw structures now deny unknown fields and normalization independently rejects
   duplicate identities, invalid or nil GUIDs, zero or overflowing geometry,
   misalignment, overlaps, out-of-disk partitions, invalid volume geometry,
   empty health evidence, invalid resize bounds, and malformed drive letters.
5. A textual command allowlist alone would not exclude dynamic invocation. The
   collector gate now rejects non-allowlisted commands, known mutation-capable
   primitives, shell/process launch, invocation operators, and PowerShell escape
   syntax. When PowerShell is installed, its parser validates the exact script
   and its command AST must contain the required module-qualified calls.

## Independent adversarial review closure

The milestone was reworked against four reproduced counterexamples from an
independent read-only review:

1. A split boot chain could normalize an inactive ESP on the Windows disk while
   the active `IsSystem` ESP was elsewhere. The adapter now requires exactly one
   active system partition, requires the ESP type, and binds it to the selected
   Windows disk.
2. An unrelated MBR or RAW disk could invalidate an otherwise supported GPT
   Windows system disk because GPT identifiers were globally mandatory. Raw
   identifiers are now nullable and strict GPT validation is scoped to the
   selected disk. Both a Rust counterexample and the end-to-end mock include
   unrelated MBR media.
3. Suppressed PowerShell observation failures could become positive servicing,
   storage, or power readiness. `SilentlyContinue` is now forbidden and all such
   reads use terminating error behavior. Missing recovery-volume health also has
   an explicit fail-closed regression.
4. `powershell.exe` and auto-loaded cmdlets could be selected through mutable
   command lookup. The launcher derives the running OS system directory through
   `GetSystemDirectoryW`, derives the executable and modules only from that native
   result, passes the verified system drive to the collector, constrains module
   dependency lookup to that tree, and uses module-qualified Windows calls. The
   static gate verifies those provenance bindings. Resize
   bounds that exclude the current partition size are also rejected explicitly.
5. Follow-up hostile inputs found that a cloned secondary disk could share the
   selected disk GUID and that a drive-letter data partition could lack volume
   health evidence while readiness remained true. Both conditions now reject
   normalization and have dedicated regressions.

## Validation

- 52 states, 86 transitions, and 15 state-model traces validate.
- 21 state-model adversarial tests pass.
- 38 Rust tests pass, including deterministic ordering, multi-disk ambiguity,
  extra Basic Data, existing JStack types, strict deserialization, impossible
  geometry, non-vacuous health, and fail-closed attestations.
- Strict Clippy passes with warnings denied.
- The library and both CLIs compile for `x86_64-pc-windows-msvc`.
- Ten Draft 2020-12 schemas and ten contract documents validate.
- The normalized inventory example regenerates byte-for-byte.
- The exact embedded PowerShell collector executes against deterministic mocks,
  then passes raw schema validation, Rust normalization, and inventory schema
  validation.
- The collector audit permits 25 read-only commands and rejects mutation escape
  hatches.

## Remaining validation boundary

This milestone has not executed live collection on a real Windows installation.
Before any mutation adapter is enabled, live output must be captured in disposable
Windows 10 and 11 UEFI VMs covering BitLocker on/off, Secure Boot on/off,
multi-disk, extra data partitions, recovery partitions, low ESP capacity,
pending reboot, unhealthy storage, and laptop power states.

Release signature trust, explicit recovery-material confirmation, and a supported
firmware-write capability check must be merged as separate evidence. Windows
Storage mutation, journaling adapters, signatures, and UEFI VM power-loss testing
remain unimplemented and unreachable.
