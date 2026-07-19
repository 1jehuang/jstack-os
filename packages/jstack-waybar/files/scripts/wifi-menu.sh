#!/bin/bash

# Get list of available wifi connections and format it for rofi
wifi_list=$(nmcli --fields "SECURITY,SSID,SIGNAL,BARS" device wifi list | sed 1d | sed 's/  */ /g' | sed -E "s/WPA*.?\S/ /g" | sed "s/^--/ /g" | sed "s/  //g" | sed "/--/d")

# Get current connection
current=$(nmcli -t -f active,ssid dev wifi | grep '^yes' | cut -d: -f2)

# Use rofi to select wifi network
chosen_network=$(echo -e "󰤭 Disconnect\n$wifi_list" | uniq -u | rofi -dmenu -i -selected-row 1 -p "WiFi Network: " -theme-str 'window {width: 600px;}')

# Get the SSID of the chosen network
chosen_ssid=$(echo "${chosen_network:3}" | awk '{print $1}')

if [ "$chosen_network" = "󰤭 Disconnect" ]; then
    nmcli connection down "$current"
elif [ -n "$chosen_network" ]; then
    # Check if we're already connected to this network
    if [ "$chosen_ssid" = "$current" ]; then
        notify-send "WiFi" "Already connected to $chosen_ssid" -i network-wireless
    else
        # Try to connect
        success=$(nmcli device wifi connect "$chosen_ssid" 2>&1)
        if [[ "$success" =~ "successfully" ]]; then
            notify-send "WiFi" "Connected to $chosen_ssid" -i network-wireless
        elif [[ "$success" =~ "password" ]] || [[ "$success" =~ "secrets were required" ]]; then
            # Need password
            password=$(rofi -dmenu -password -p "Password for $chosen_ssid: " -theme-str 'window {width: 400px;}')
            if [ -n "$password" ]; then
                nmcli device wifi connect "$chosen_ssid" password "$password"
                notify-send "WiFi" "Connected to $chosen_ssid" -i network-wireless
            fi
        else
            notify-send "WiFi" "Failed to connect to $chosen_ssid" -i network-error
        fi
    fi
fi