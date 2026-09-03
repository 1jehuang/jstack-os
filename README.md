# jstack OS

An agent-native, Arch-based Linux distribution. Everything is scriptable,
machine-readable, and pre-configured for AI coding agents: niri (IPC-first
compositor), terminal remote control, structured system introspection, and
preinstalled agent harnesses.

## Layout

- `packages/` - PKGBUILDs for jstack meta/config packages
  - `jstack-base/` - policy: services, keyd, NM/iwd, fish, **no snapshots**
  - `jstack-agent/` - jcode preinstalled from a pinned release
  - `jstack-terminals/` - kitty (remote-control socket) + foot defaults
  - `jstack-niri/` - niri desktop: config, keymap, helper scripts
  - `jstack-waybar/`, `jstack-network/`, `tofi-jstack/`
- `install/` - `jstack-install.sh`: full install from an Ubuntu/Debian or Arch
  host via pacstrap. See `docs/INSTALL_FROM_UBUNTU.md`
  - `jstack-scheduler/` - scx_lavd CPU scheduler (sched_ext), enabled by default
  - `jstack-firefox/` - Firefox policies, OLED theme, curated extensions
- `installer/` - executable no-USB Windows installer state model and tools
- `docs/installer/` - installer architecture, safety model, and generated graph
- `iso/` - archiso and RAM-installer profile (to come)
- `docs/TRIAGE.md` - the keep/drop decision log for everything migrated
  from the reference machine

## Design rules

1. Nothing is hand-copied onto the ISO. Everything ships inside a package.
2. User-facing defaults live in `/etc/skel`, shared assets in
   `/usr/share/jstack`, helper scripts in `/usr/lib/jstack/scripts`.
3. Every migrated config records a decision in `docs/TRIAGE.md`
   (distro / personal / hardware / cruft).
4. No hardcoded `/home/<user>` paths, hostnames, serials, or credentials in
   anything distro-bucketed.

## Building a package

```sh
cd packages/jstack-niri
makepkg -f
```
