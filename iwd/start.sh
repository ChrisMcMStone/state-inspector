#!/bin/bash
set -e

# To be sure other iwd instances are killed
killall iwd 2> /dev/null || true
sleep 0.5

modprobe mac80211_hwsim radios=4 || true
sleep 0.5
rfkill unblock wifi
ifconfig wlan1 down
ifconfig wlan2 down
iw wlan1 set type monitor
iw wlan2 set type monitor
ifconfig wlan1 up
ifconfig wlan2 up
iw wlan1 set channel 6
iw wlan2 set channel 6
ifconfig hwsim0 up

# Queue execution of ./iwd-setap.py and iwctl using a background bash process
(sleep 3 && ./iwd-setap.py wlan0 && iwctl ap wlan0 start test-network testing123) &

# Start iwd process (this will block)
./iwd/src/iwd -d -i wlan0
