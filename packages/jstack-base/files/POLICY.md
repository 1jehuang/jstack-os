# jstack-base policy

Decisions baked into every jstack OS install, taken from the reference machine.

- **No filesystem snapshotting.** snapper, snap-pac, timeshift and grub-btrfs
  are blocked by a pacman PreTransaction hook. btrfs is still the root
  filesystem (zstd:3, @ / @home / @log / @pkg subvolumes) but nothing takes
  snapshots behind your back. Delete the hook to opt back in.
- **Wi-Fi via NetworkManager + iwd backend.** `iwd.service` and
  `NetworkManager.service` enabled by preset.
- **keyd** enabled, Right Alt -> Enter (system-wide). Caps -> Esc lives in the
  niri xkb file (jstack-niri).
- **Passwordless sudo** for the primary user (`/etc/sudoers.d/15-jstack-nopasswd`).
  Remove that file to require a password.
- **fish** is the login shell. tty1 login autostarts `niri-session`.
- **TLP** enabled with powersave governor, performance EPP on AC.
- **earlyoom**, **bluetooth**, **fstrim.timer** enabled.
- **jcode** preinstalled from a pinned release (jstack-agent);
  `JCODE_NO_AUTO_UPDATE=1` so pacman owns the binary.
- **kitty** ships with `allow_remote_control yes` and
  `listen_on unix:/tmp/kitty.sock` (jstack-terminals).
