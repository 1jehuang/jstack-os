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

## Pending audits

- [ ] waybar config (+detect-compositor.sh)
- [ ] tofi config + /usr/local/bin/tofi-drun fork
- [ ] kitty / foot configs
- [ ] keyd system config
- [ ] dunst config
- [ ] shell (fish?), prompt, CLI tools
- [ ] agent layer (jcode, kitty socket, MCP, jq/jc defaults)
- [ ] full pacman -Qen (229 explicit packages)
- [ ] AUR packages (42)
- [ ] /etc/skel dotfiles beyond niri
