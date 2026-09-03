# jstack OS Wayland defaults
set -gx XDG_SESSION_TYPE wayland
set -gx XDG_CURRENT_DESKTOP niri
set -gx XDG_SESSION_DESKTOP niri
set -gx QT_QPA_PLATFORM wayland
set -gx GDK_BACKEND wayland,x11
set -gx MOZ_ENABLE_WAYLAND 1
set -gx NIXOS_OZONE_WL 1
fish_add_path -g ~/.local/bin ~/.cargo/bin
