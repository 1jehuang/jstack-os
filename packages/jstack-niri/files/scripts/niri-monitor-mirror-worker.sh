#!/usr/bin/env bash
set -euo pipefail

source_output=${1:?usage: niri-monitor-mirror-worker.sh SOURCE_OUTPUT}

# This is a software mirror because niri does not provide native output cloning.
# wf-recorder captures the laptop output and mpv presents it fullscreen elsewhere.
wf-recorder \
    -y \
    -o "$source_output" \
    -r 30 \
    -c libx264 \
    -p preset=ultrafast \
    -p tune=zerolatency \
    -m mpegts \
    -f /dev/stdout \
    2> >(sed -u 's/^/[wf-recorder] /' >&2) | mpv \
        --no-config \
        --profile=low-latency \
        --cache=no \
        --untimed \
        --demuxer-lavf-format=mpegts \
        --no-audio \
        --fullscreen \
        --fs-screen=current \
        --no-osc \
        --osd-level=0 \
        --cursor-autohide=always \
        --input-default-bindings=no \
        --wayland-app-id=niri-monitor-mirror \
        --title='Laptop Screen Mirror' \
        -
