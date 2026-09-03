# jstack OS Triage Log

Every item from the reference machine gets exactly one bucket:
**distro** (ships for everyone), **personal** (stays on Jeremy's machine),
**hardware** (optional per-machine package), **cruft** (dropped).

Rule of thumb: unsure → personal. Promoting later is easy, de-shipping is a
breaking change.

## niri (audited 2026-07-18)

### config.kdl

| Item | Bucket | Notes |
|---|---|---|
| input (repeat 250/25, tap, natural-scroll, numlock) | distro | |
| custom xkb keymap (Caps→Esc, RAlt→Mod5) | distro | installed to /usr/share/jstack/xkb |
| hot-corners off | distro | |
| output "DP-1" (MSI 4K) block | hardware | dropped from distro config; auto-config default |
| output "eDP-1" position | hardware | dropped |
| layout (gaps 0, presets, focus-ring gradient, struts) | distro | |
| spawn: load-xkb.sh | cruft | X11-only (xkbcomp on $DISPLAY); niri loads keymap natively via xkb file. Kept script in repo, not spawned |
| spawn: waybar via detect-compositor.sh | distro | simplified to plain `waybar` for now; revisit when waybar config is triaged |
| spawn: foot --server | distro | |
| spawn: awww wallpaper (pure_black.png) | distro | wallpaper installed to /usr/share/jstack/wallpapers |
| spawn: swayidle-start.sh | distro | |
| spawn: monitor-above.sh | distro | genericized: MSI hardcode → JSTACK_MONITOR_ABOVE_EXCLUDE env |
| prefer-no-csd, xwayland-satellite, screenshot-path | distro | |
| blur settings | distro | |
| animations (150ms ease-out-expo, spring workspace) | distro | |
| window rules: PiP float, corner radius 6, terminal widths, dunst opacity, tofi blur, open-focused | distro | |
| window rule: wezterm workaround | cruft | wezterm not shipped |
| window rules: ghostty, nvim-kitty, alacritty-small, ripdrag | personal | apps not in base; user config can re-add |
| workspaces 1-5 | distro | |
| jcode launch hotkeys (Super+;, ', [, ], \\) | personal | hardcoded /home/jeremy project paths |
| Alt+Space tofi launcher | distro | simplified: tofi-drun-workspace.sh depends on /usr/local fork; shipped as plain tofi-drun |
| Alt+W wifi-pick, Alt+Y todoist | personal | ~/.local/bin scripts; wifi-pick candidate for promotion later |
| Ctrl+Shift+N firefox private window | distro | |
| Alt+BracketLeft handterm | personal | |
| Alt+G lazygit, Alt+/ jcode-here, Alt+I/P jcode-desktop, Alt+;/:/'/B/] jcode variants | personal | jcode selfdev workflow |
| Alt+5/6/7/0/Minus jcode onboarding tests | personal | dev-only test binds; distro restores focus-workspace 5-7 |
| Alt+Z/O/D/Shift+O ffp file picker | personal | ~/.local/bin/ffp; promotion candidate |
| Alt+1-4 width presets, Alt+8/9 workspaces, Alt+Shift+0 last-workspace | distro | |
| Alt+H/J/K/L nav, Alt+Shift+HJKL move, Mod5+HJKL monitor | distro | core identity |
| Alt+C/V/A/comma/period/backspace wtype helpers | distro | |
| Alt+Tab previous window, Alt+R/F, Alt+Q | distro | |
| volume/media/brightness keys, F1-F11 | distro | |
| Ctrl+Backslash toggle-recording | personal | ~/.local/bin script not audited yet |
| F12 notify-send placeholder | cruft | |
| Print/Ctrl+Print/Alt+Print screenshots, Ctrl+Alt+Delete quit | distro | |

### ~/.config/niri/ files

| Item | Bucket | Notes |
|---|---|---|
| config.kdl | distro | sanitized copy above |
| ~28 config.kdl.bak* files | cruft | not copied |
| banish-window.sh | cruft | bind disabled 2026-05-11 |
| cycle-monitor-layout.sh | distro | shipped |
| firefox-private-window-shortcut.sh | distro | shipped |
| focus-last-workspace.sh | distro | shipped |
| load-xkb.sh | cruft* | copied but not wired; X11-only |
| monitor-above.sh | distro | genericized |
| niri-monitor-mirror-worker.sh | distro | helper for cycle-monitor-layout |
| organize-workspaces.py | distro | shipped |
| quick-switch.sh | distro | shipped |
| random-wallpaper.sh | personal | hardcoded personal wallpaper list |
| semantic-organize.sh | personal | bind removed; not audited |
| send-nav-key.sh | cruft | binds disabled (keyd handles it) |
| swayidle-start.sh | distro | shipped |
| switch-monitor-focus.sh | distro | shipped |

### Packages implied by niri setup

| Package | Bucket | Notes |
|---|---|---|
| niri, waybar, foot, kitty, swayidle, playerctl, brightnessctl, wtype, xwayland-satellite, dunst, wireplumber, jq, awww | distro | all official repos |
| tofi | distro | **AUR** - must be prebuilt into jstack overlay repo |
| fuzzel, rofi | cruft | binds disabled |
| keyd | pending | referenced in comments (win-key nav); audit /etc/keyd next |

## waybar (audited 2026-07-19)

### config modules

| Item | Bucket | Notes |
|---|---|---|
| clock, cpu, memory, temperature, disk, pulseaudio, tray, niri/window | distro | temperature: dropped hardcoded hwmon2 path (machine-specific), waybar autodetects |
| custom/workspaces (niri-workspaces-rs, Rust) | distro | built from source in PKGBUILD, /usr/lib/jstack/waybar |
| custom/battery (battery-rs, Rust) | distro | decimal battery readout |
| custom/window-uptime (window-uptime-rs, Rust) | distro | |
| custom/net (net-status py + wifi-menu.sh + dbus-monitor.sh) | distro | unified network module; dbus-monitor.sh not yet spawned anywhere (TODO: wire as user service or spawn-at-startup) |
| custom/jcode-sessions, jcode-pss, jcode-ambient | personal | promotion candidates once jstack-agent package exists |
| custom/yc-demo-day | personal | |
| custom/cargo-build | personal | dev workflow |
| custom/spotui, stop-song-launcher | personal | |
| custom/airpods, airpods-case (+icons, dbus py) | personal | niche hardware; promotion candidate |
| custom/whisper (whisper-rs) | personal | depends on local whisper dictation stack |
| custom/recording | personal | depends on toggle-recording script |
| custom/vram, audio-device, camera, docker, hotspot, wifi, window-number | cruft | unreferenced in module lists or superseded by custom/net |
| config-hyprland | cruft | not shipping hyprland |
| detect-compositor.sh | distro | shipped |
| style.css | distro | sanitized: removed personal module styles + /home icon urls |
| niri-workspaces .bak/.running binaries, __pycache__ | cruft | |
| battery-decimal.py, airpods.sh/dbus.sh, niri-events.sh, niri-workspaces.sh | cruft | superseded by Rust rewrites |
| waybar-power-monitor-rs, whisper-rs | personal | not referenced by shipped config |

### Packages implied

| Package | Bucket | Notes |
|---|---|---|
| waybar, networkmanager, rofi-wayland, libnotify, ttf-jetbrains-mono-nerd, python | distro | wifi-menu uses rofi; nerd font needed for icons |

## network stack: wifi-pick + captive portal + tofi (audited 2026-07-19)

| Item | Bucket | Notes |
|---|---|---|
| ~/.local/bin/wifi-pick (tofi Wi-Fi picker) | distro | promoted from personal. Sanitized: /usr/local tofi fork ref → plain tofi, helper paths → /usr/bin |
| ~/.local/bin/captive-portal-helper | distro | opens/auto-accepts captive portals |
| ~/.local/bin/captive-portal-autoaccept (900-line engine) | distro | no personal data found |
| ~/.local/bin/captive-portal-watch (notification watcher) | distro | |
| captive-portal-helper.service/.timer, captive-portal-watch.service | distro | installed as system-wide user units + preset (auto-enabled) |
| Wi-Fi boot recovery service/timer | distro | generic health check; recovers iwd ENFILE failures when iwd is active and only reloads kernel modules when Intel iwlwifi is loaded. No-op without wireless hardware |
| Intel BE200/BE201 firmware crash signature | hardware | observed `Microcode SW error` can leave duplicate wlan interfaces; handled conditionally by the distro recovery service rather than hardcoding Intel module options for everyone |
| ~/src/tofi fork (typo-tolerant matching, Ctrl-f/b/g/h/m) | distro | packaged as tofi-jstack, builds from github.com/1jehuang/tofi (public), provides/conflicts tofi. Replaces AUR tofi |
| ~/.config/tofi/config (fullscreen orange/black theme) | distro | ships in tofi-jstack /etc/skel |
| tofi-drun-workspace.sh | distro | shipped as /usr/bin/tofi-drun-workspace in tofi-jstack. Sanitized: /usr/local fork → plain tofi-drun, LAZYGIT_HERE_* env → JSTACK_ORIGIN_* |
| ~/.cache captive portal state files | personal | runtime state, never shipped |

Note: jstack-niri Alt+W now spawns /usr/bin/wifi-pick.

## tofi modes and scripts (audited 2026-09-03)

| Item | Bucket | Notes |
|---|---|---|
| ~/.config/tofi/config | distro | already shipped, identical to live |
| ~/.local/bin/tofi-bring-here (window picker) | distro | shipped in tofi-jstack, bound Alt+Shift+A (live bind used rofi-bring-here; tofi version is the canonical one) |
| scripts/power-menu.sh + power-menu.conf | distro | shipped as tofi-power-menu, conf in /usr/share/jstack/tofi. Sanitized: swaylock → loginctl lock-session, SF Pro Display → monospace. Bound Alt+Shift+E |
| ~/.local/bin/tofi-bitwarden | personal | password manager choice |
| scripts/calculator.sh, simple-timer.sh | cruft | trivial, unbound |
| scripts/claude-query.sh, codex-query.sh | personal | dev tooling |
| scripts/theme-menu.sh, theme-switcher.sh, themes/ | cruft | only two themes, one is the shipped default |
| scripts/benchmark-tofi.sh, launcher-shootout.sh, wofi-benchmark.sh | cruft | benchmarks |
| config.backup | cruft | |

## firefox (audited 2026-09-03)

Reference profile: `~/.mozilla/firefox/*.default-release`. Shipped as `jstack-firefox`.

| Item | Bucket | Notes |
|---|---|---|
| user.js: OLED black colors, compact-dark theme, blank home/newtab, activity-stream off, firefox-view off, bookmarks bar hidden | distro | |
| user.js: `ui.key.menuAccessKey 0` (Alt+letter does not open menubar) | distro | required so niri Alt binds are not eaten |
| user.js: telemetry/datareporting off, first-run/whats-new/uitour off, checkDefaultBrowser off | distro | also enforced via policies.json |
| user.js: `widget.use-xdg-desktop-portal.file-picker 1`, `allow-pipewire false` | distro | Wayland portal file picker; camera workaround |
| user.js: devtools.chrome.enabled, browserconsole.contentMessages | distro | agent debugging |
| user.js: ~40 legacy webdriver/marionette/security.warn_*/safebrowsing-dummy prefs | cruft | injected by an old automation harness; dropped |
| user.js: signon.rememberSignons false, xpinstall.signatures.required false, extensions.enabledScopes | personal | user choice / unsafe default |
| user.js: app.update.*, extensions.update.* off | distro | moved into policies.json (DisableAppUpdate); extension updates stay on |
| chrome/userChrome.css (OLED black) | distro | shipped verbatim |
| /etc/firefox/policies/policies.json (vimium auto-install) | distro | extended to full curated set |
| ext: uBlock Origin, Vimium, SponsorBlock, Hide YouTube Shorts, Bitwarden | distro | via ExtensionSettings normal_installed (user can remove) |
| ext: Redirector, ff2mpv, Bookface Companion | personal | need per-user rules / mpv native host / YC account |
| ext: Dark Reader, Tridactyl (both disabled) | cruft | |
| ext: browser-agent-bridge + ~/.mozilla/native-messaging-hosts/firefox_agent_bridge.json | pending | jcode's Firefox bridge; ships with agent layer (jstack-agent), not here |
| ~/.config/tridactyl/tridactylrc | cruft | tridactyl disabled |
| cookies, logins, places, sessionstore, containers | personal | never shipped |

## base system policy (audited 2026-09-03)

| Item | Bucket | Notes |
|---|---|---|
| snapper (installed, timers disabled, empty /.snapshots) | cruft | **explicitly banned**: jstack-base conflicts + pacman hook. btrfs stays, snapshots do not |
| btrfs layout @ @home @log @pkg, zstd:3, discard=async | distro | installer reproduces it |
| systemd-boot, timeout 1 | distro | resume=/hibernate offset | hardware | not shipped |
| keyd rightalt=enter | distro | jstack-base |
| NetworkManager wifi.backend=iwd | distro | jstack-base |
| tlp, earlyoom, bluetooth, iwd, NM enabled | distro | preset in jstack-base |
| fish login shell + tty1 autologin -> niri-session | distro | skel conf.d + autologin template |
| ~/.profile Wayland exports | distro | moved to /etc/fish/conf.d/jstack-env.fish; nvm/cargo/npm PATH lines are personal |
| fish aliases (wifilogin, chrome ozone, volumeset) | personal | |
| kitty.conf (remote control socket, black, JetBrainsMono) | distro | jstack-terminals, byte-identical to reference |
| foot.ini | distro | dropped personal BROWSER=/home/jeremy/bin path |
| jcode (~/.local/bin launcher + ~/.jcode/builds) | distro | jstack-agent: pinned release tarball -> /usr/lib/jstack/agent, /usr/bin/jcode symlink, auto-update off |
| ~/.local/bin/jcode-* helper scripts (60+) | personal | selfdev workflow |

## Pending audits

- [x] kitty / foot configs
- [x] keyd system config
- [x] agent layer (jcode, kitty socket)
- [ ] dunst config
- [ ] shell (fish?), prompt, CLI tools
- [ ] agent layer (jcode, kitty socket, firefox agent bridge, MCP, jq/jc defaults)
- [ ] full pacman -Qen (229 explicit packages)
- [ ] AUR packages (42)
- [ ] /etc/skel dotfiles beyond niri

## CPU scheduler (audited 2026-09-03)

| Item | Bucket | Notes |
|---|---|---|
| scx_lavd via sched_ext (scx-scheds 1.1.2, stock `linux` kernel) | distro | packaged as jstack-scheduler: `jstack-scx.service` + `/etc/default/jstack-scx` (scheduler/flags overridable). Enabled by preset |
| hand-written /etc/systemd/system/scx-lavd.service | cruft | replaced by the packaged unit; `ConditionPathIsDirectory=/sys/kernel/sched_ext` makes it a no-op on kernels without sched_ext |
| NVMe I/O scheduler `none`, sched_autogroup=1 | distro | kernel defaults, nothing to ship |
