#!/bin/bash
# Launch swayidle with a 10-minute idle timeout that powers monitors off and back on.

exec swayidle \
    timeout 600 "niri msg action power-off-monitors" \
    resume "niri msg action power-on-monitors"
