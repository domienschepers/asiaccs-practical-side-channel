modprobe mac80211_hwsim radios=3
iwconfig wlan2 mode monitor
ifconfig wlan1 up
ifconfig wlan2 up
ip addr add 192.168.0.10 dev wlan1
