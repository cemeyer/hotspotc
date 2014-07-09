#Introduction

*Hotspotc* is a small daemon based on `prahladyeri/hotspotd` to create a wifi
hotspot on linux. It depends on *hostapd* for AP provisioning and *dnsmasq* to
assign IP addresses to devices.

Hotspotc works by creating a virtual NAT (Network address transation) table
between your connected device and the internet using Linux' *iptables*.

#Dependencies
 * *dnsmasq* (typically pre-installed on most linux distributions)
 * *hostapd* for AP provisioning

#How to use

Root is needed to start and stop hotspots.

To start a hotspot:
```
./hotspotc start
```

To stop the hotspot:
```
./hotspotc stop
```

The first time you run `hotspotc`, it will ask you for configuration values for
SSID, password, etc. Alternatively, you may run:
```
./hotspotc configure
```

#Testing status

Ahahahaha.
