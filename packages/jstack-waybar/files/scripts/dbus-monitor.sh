#!/bin/bash
# Monitor D-Bus for Bluetooth and NetworkManager events, signal waybar to update.

AIRPODS_SIGNAL=9
NETWORK_SIGNAL=10

# Track last signal time to debounce
LAST_BT=0
LAST_NET=0
DEBOUNCE_MS=500

signal_waybar() {
    local sig=$1
    pkill -RTMIN+$sig waybar 2>/dev/null
}

# Monitor system bus for BlueZ and NetworkManager
dbus-monitor --system "type='signal',sender='org.bluez'" \
    "type='signal',sender='org.freedesktop.NetworkManager'" 2>/dev/null | \
while read -r line; do
    NOW=$(date +%s%3N)

    # Bluetooth events
    if echo "$line" | grep -qE "org\.bluez\.(Device1|MediaTransport1)|interface=org\.bluez"; then
        if (( NOW - LAST_BT > DEBOUNCE_MS )); then
            signal_waybar $AIRPODS_SIGNAL
            LAST_BT=$NOW
        fi
    fi

    # NetworkManager events (state changes + property changes like signal strength).
    # Match both dotted interface names and slashed object paths.
    if echo "$line" | grep -qE "org[\./]freedesktop[\./]NetworkManager|StateChanged"; then
        if (( NOW - LAST_NET > DEBOUNCE_MS )); then
            signal_waybar $NETWORK_SIGNAL
            LAST_NET=$NOW
        fi
    fi
done
