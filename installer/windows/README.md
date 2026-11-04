# Install Jstack OS from Windows

Double-click `Install-JStack.cmd` (or run `Install-JStack.ps1` as administrator).
No USB stick, no BIOS settings. Secure Boot stays on.

## What it does

1. Checks the PC: 64-bit Windows booted in UEFI mode, GPT disk, enough room on C:,
   BitLocker not mid-encryption.
2. Asks for the JStack username and password (empty password allowed).
3. Downloads the payload from the latest GitHub release and checks every file
   against `manifest.json` (SHA256).
4. Shrinks C: (64 GB by default, `-SizeGB` to change; Windows keeps at least 20 GB free)
   and writes the JStack Btrfs root into the new partition, then reads it back to verify.
5. Copies four files (about 4 MB) to `\EFI\jstack\` on the existing EFI partition.
   Windows boot files are not touched.
6. Pauses BitLocker for two restarts, adds a "Jstack OS" firmware boot entry and
   restarts into it once.

On first boot JStack creates the account, copies saved Wi-Fi networks and the time
zone from Windows, grows the filesystem to fill the partition, and erases the answer
file from the EFI partition.

If any step fails the installer undoes what it did. `Uninstall-JStack.ps1` removes
JStack later and gives the space back to C:.

## Why Secure Boot can stay on

PC firmware trusts Microsoft's keys. The boot chain is:

    firmware -> shimx64.efi (signed by Microsoft) -> grubx64.efi (signed by Canonical)
             -> vmlinuz (signed by Canonical) -> JStack userland (Arch based)

These are Ubuntu's signed shim, GRUB and kernel, with pinned versions checked when the
payload is built. JStack uses the Ubuntu kernel and its modules in place of the Arch
kernel. pacman is set to ignore `linux*`, so an unsigned kernel never gets installed.

## Switching between Windows and JStack

- At power-on, a menu offers Jstack OS, Windows and firmware settings.
- In Windows, the Start menu has **Restart into JStack**.
- In JStack, the app menu has **Restart into Windows**.

These shortcuts use the firmware BootNext variable, so each OS is started directly by
the firmware. With BitLocker on, this is the way to switch. Picking Windows from the GRUB
menu changes the TPM measurements and Windows asks for the recovery key. With BitLocker
on, the installer therefore keeps Windows as the default and adds JStack as a second
entry.

## Options

    Install-JStack.ps1 [-SizeGB N] [-Username u] [-FullName n] [-Password s | -NoPassword]
                       [-Hostname h] [-DefaultOS auto|jstack|windows] [-NoWifi]
                       [-PayloadDir folder] [-PayloadUrl url] [-NoReboot] [-Yes] [-DryRun]

`-DryRun` runs every check and changes nothing.

## Building the payload (maintainers)

    iso/build.sh ...                                   # build a JStack live ISO
    installer/windows/build-payload.sh --iso /abs/jstack-live.iso --out /abs/payload

Upload the contents of `payload/` with `Install-JStack.ps1`, `Install-JStack.cmd` and
`Uninstall-JStack.ps1` as assets of a GitHub release.

## Testing

`vm/lab.py` builds a Windows 11 VM with Secure Boot (Microsoft keys only), a TPM and an
NVMe disk, then drives the installer inside it:

    installer/windows/vm/lab.py build-base [--bitlocker]
    installer/windows/vm/lab.py up test --fresh

## Status

The Secure Boot chain has been proven in QEMU with Microsoft-keys-only firmware.
The full installer has not yet been run end to end in the test VM.
