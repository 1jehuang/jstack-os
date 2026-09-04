# Acceptance evidence

Last verified: 2026-09-04

This document maps the installation contract and the no-USB handoff requirements
to observed acceptance behavior. No real credential values are recorded here.

## Acceptance interfaces exercised

1. `install/vm/test-ubuntu.sh`
   - Booted a fresh Ubuntu 24.04 image under QEMU/OVMF.
   - Invoked the public whole-disk installer against a blank 24 GiB disk.
   - Booted that installed disk under OVMF with a different device enumeration.
   - Final result: exit 0, `E2E: INSTALL_OK`, `E2E-BOOT: DONE`, and all 20
     policy assertions passed.
2. `install/seed/restore-seed.sh <encrypted-bundle> jeremy`
   - Invoked inside the installed JStack VM with an AES-256-CBC/PBKDF2 fixture.
   - Final result: GitHub CLI auth, Jcode provider environment, and NetworkManager
     Wi-Fi state restored with the expected ownership and mode 0600.
   - A wrong-passphrase invocation exited nonzero before mutation. Hashes of the
     existing host authentication files were unchanged.
3. `install/jstack-install.sh --disk /dev/nvme0n1 --user guard-test --yes`
   - Invoked on the mounted Ubuntu system disk to exercise the destructive guard.
   - Final result: exit 1 with the mounted-disk refusal. The partition/erase stage
     was not reached.
4. Customized Arch ISO booted from an ext4-backed virtual NVMe using the same
   `img_dev`, `img_loop`, and `copytoram=y` interface as the physical GRUB entry.
   - Final result: Arch reached multi-user, copied the live image to RAM, launched
     the installer automatically on tty1, verified both payload checksums, and
     visibly reached `Seed passphrase:`.
5. Current Ubuntu passwordless sudo was tested after `sudo -K` cleared cached
   credentials.
   - Final result: `sudo -n id -u` returned 0, protected-file access succeeded,
     the sudoers include and complete configuration parsed with `visudo`, and the
     include is root-owned mode 0440.

## Requirement-to-check matrix

| Requirement or public output | Concrete check | Observed result |
|---|---|---|
| Install from Ubuntu | Phase 1 of `install/vm/test-ubuntu.sh` | `E2E: INSTALL_OK` |
| Installed system boots under UEFI | Phase 2 boots the resulting disk with OVMF | `E2E-BOOT: DONE` |
| Disk identity survives enumeration changes | Install target was `/dev/vdb`; installed boot exposed it as `/dev/vda`; `/etc/fstab` probe rejected `/dev/*` sources | `fstab_stable=yes` |
| Whole-disk safety | Public CLI invoked against mounted laptop disk | Refused before erase stage |
| btrfs root and compression | `findmnt` on the booted result | `btrfs`, `compress=zstd:3`, SSD/discard options, `subvol=/@` |
| `@ @home @log @pkg` subvolumes | `btrfs subvolume list /` in the booted result | All four present |
| No snapshots or snapshot tools | Package query, subvolume query, pacman-hook check | `snapper=0`, `snapshots=0`, hook present |
| systemd-boot and fallback | Real OVMF boot plus loader probes | timeout 1, normal entry and fallback entry present |
| niri desktop | Command lookup in the booted result | `/usr/bin/niri` |
| waybar, tofi, dunst | Command lookups in the booted result | All present in `/usr/bin` |
| kitty and foot | Command lookups and kitty config probe | Both present; remote control socket configured |
| fish login shell | `getent passwd` on first boot | `/usr/bin/fish` |
| tty1 autologin | Installed systemd drop-in probe | Present |
| Graphical startup | `systemctl get-default` | `graphical.target` |
| NetworkManager with iwd | Config probe and service enablement | backend count 1; NetworkManager and iwd enabled |
| keyd policy | Config probe and service enablement | config present; service enabled |
| TLP and earlyoom | Service enablement plus packaged TLP policy probe | Both enabled; powersave governor and performance EPP on AC |
| Bluetooth | Service enablement probe | enabled |
| scx_lavd scheduler | Package/command and `jstack-scx.service` probes | installed and enabled |
| Jcode pinned release | Run `/usr/bin/jcode --version` after boot | `jcode v0.81.4 (896f866eb)` |
| Jcode in fish with updates disabled | Run Jcode from `fish -lc` | version succeeded; `JCODE_NO_AUTO_UPDATE=1` |
| GitHub CLI available for restored auth | Command lookup after boot | `/usr/bin/gh` |
| Primary-user passwordless sudo | Nested `sudo -n` check after boot | `sudo_nopasswd=yes` |
| All JStack policy packages | `pacman -Q` after boot | base, agent, terminals, niri, network, waybar, scheduler, Firefox, desktop apps, and tofi present |
| Encrypted seed integration | Real restore script in installed VM | GitHub, Jcode, and Wi-Fi fixture outputs passed ownership/mode/content checks |
| Wrong seed password safety | Real restore script with wrong password and before/after hashes | Nonzero exit; existing auth unchanged |
| No USB and automatic launch | Actual customized ISO loop-booted from virtual internal NVMe | tty1 automatic UI rendered without a launch command |
| Visible progress | Captured 1280x800 tty1 console | Banner, RAM copy, checksum results, and passphrase prompt visible |
| Payload integrity | `sha256sum --check --strict` | ISO, source payload, and encrypted seed all passed |
| One-time physical handoff | GRUB environment and generated entry | `next_entry=arch-internal-installer`; entry uses the checked custom ISO |
| Ubuntu sudo without password | Clean credential-state `sudo -n` checks | root execution and protected access passed |

## Physical acceptance boundary

Secure Boot is still enabled. Only the user can disable it in Dell firmware.
The physical disk has therefore not been erased or booted into the new system.
After Secure Boot is disabled, the armed one-time entry will exercise the same
ISO path validated above. The real encrypted seed is checksum-valid, but its
user-held passphrase was intentionally not extracted or recorded. Its final
physical decryption and the explicit disk-erasure confirmation remain user
acceptance steps.
