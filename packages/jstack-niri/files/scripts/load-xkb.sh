#!/bin/bash
# Load custom XKB configuration for Right Alt + vim arrow keys

xkbcomp -w0 "/usr/share/jstack/xkb/custom.xkb" "$DISPLAY"
