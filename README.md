# NAT-PMP-Spoof
Spoofing NAT-PMP on Windows. There were no good NAT-PMP apps for Windows so I made one.

# What it does
The project allows user to craft a packet and send it to Gateway for port mapping. It supposed to work with UPNP as well, and works with miniupnpd.
User may specify any IPv4 address, as opposed to natpmpc. Since it will impersonate specified host, the host either need to be reachable with NetBIOS, or hosts's addresses need to be passed to the program.

# Libraries in use
* Win32, iphlpapi ;
* PcapPlusPlus and all of it's dependencies https://github.com/seladb/PcapPlusPlus ;

# Compatibility with multihomed networks
Both UPNP and NAT-PMP aren't designed to work under such conditions. You can still manually specify IP addresses of gateways and create mapping on each gateway, however.
