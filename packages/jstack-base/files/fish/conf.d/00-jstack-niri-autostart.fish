# jstack OS: start niri when logging in on tty1 with no session running.
# niri-session spawns a login fish; the guard var stops infinite recursion.
if test -z "$DISPLAY"; and test -z "$WAYLAND_DISPLAY"; and test (tty) = "/dev/tty1"; and not set -q NIRI_SESSION_AUTOSTARTED
    set -gx NIRI_SESSION_AUTOSTARTED 1
    exec niri-session
end
if status is-interactive
    set -g fish_greeting ""
end
