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
