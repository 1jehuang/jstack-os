# Disposable Windows VM laboratory

This directory contains the file-only QEMU/KVM harness used to prove the Windows
installer without attaching a host disk.

The evidence and acceptance contract is `docs/installer/VM_PROOF.md`.

## Safety rule

All mutable VM state must be a regular file below
`$JCODE_SCRATCH_DIR/jstack-windows-vm`. The harness rejects symlinks, device
nodes, nested mounts, paths escaping the workspace, and non-qcow2 disks. QEMU
must run as the unprivileged user. Do not add a generic drive, blockdev,
host-device, or arbitrary QEMU-argument option.

## Commands

```sh
cd installer/vm
make test
make check
make init
make host-check
make full-check
```

`make init` records host capability evidence in
`$JCODE_SCRATCH_DIR/jstack-windows-vm/evidence/host.json`.

`make check` is host-independent and is included in the installer repository's
default gate. `make full-check` additionally requires the local KVM, QEMU, OVMF,
memory, disk-space, and private-workspace envelope.

The fixed launcher uses the profile-pinned QEMU 11.0 machine, NVMe system disk,
e1000e network controller, TPM CRB interface, and only pre-opened regular-file
block backends. Its current launch command proves the safety interlock, not a
completed Windows or JStack installation.

VM creation, unattended installation, snapshot management, guest control, and
fault-campaign commands will be added behind the same file-only interlock.

## Host memory policy for base-image builds

A base-image build is a single unresumable job that runs for most of an hour, so
it interacts badly with a userspace OOM killer, and this cost two real runs
before it was understood.

On the reference machine `earlyoom` runs with `--sort-by-rss`, which always
selects the largest resident process. The guest is a 4 GiB VM, so it is always
the largest, which made the one irreplaceable job the structurally preferred
victim over the restartable `cargo` compile that caused the pressure. Both kills
arrived that way, once at roughly 40% of an install and once at roughly 95%.

Two mitigations, in the order they should be reached for:

1. Host policy. `qemu-system-x86_64` and its paired `swtpm` belong in earlyoom's
   `--avoid` set, and compilers belong in `--prefer`. A killed `rustc` costs a
   rebuild; a killed install costs the whole run. This is a host configuration
   change, not a repository one, so it is recorded here rather than enforced by
   code.
2. Build-time refusal. `base_image_build.py` checks the memory envelope before
   it launches anything and refuses to start a build the host cannot hold. This
   cannot prevent a kill that arrives 40 minutes later, so it is a floor and not
   a guarantee.

Do not run a parallel compile alongside a base-image build on a 16 GiB host
without swap. The two peak against each other, and the build is the expensive
one to lose.

Because a kill cannot be entirely prevented, it must at least be legible. QEMU
handles `SIGTERM` by shutting down cleanly and exiting *zero*, so a signalled
guest is invisible in the exit code and the build would otherwise proceed to
inspect a half-written disk and report a partition-table error, which blames the
wrong component. The build therefore reads QEMU's own termination notice out of
its log before trusting the disk. `tools/watch_base_image_build.sh` reports the
phase from the guest's disk growth, which is what distinguishes a slow install
from a stalled one.
