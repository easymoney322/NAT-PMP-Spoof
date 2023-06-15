# NAT-PMP-Spoof
Spoofing NAT-PMP on Windows. There were no good NAT-PMP apps for Windows so I made one.

# What it does
The project allows user to craft a packet and send it to Gateway for port mapping. It supposed to work with UPNP as well, and works with miniupnpd.
User may specify any IPv4 address, as opposed to natpmpc. Since it will impersonate specified host, the host either need to be reachable with NetBIOS, or hosts's addresses need to be passed to the program.

# Usage
* -help  - Shows this message;
* -PH xxxxx  -  Port on the host, who we are impersonating (REQUIRED);
* -DA xxx.xxx.xxx.xxx  - IPv4 of host we will be impersonating (REQUIRED);
* -PO xxxxx  - Port on the GateWay (Optional, defaults to specified host port)" << std::endl //If not passed, will be the same as port on the host;
* -T xxxxxxxxx  - Time of the binding in seconds: 0 for infinite, the max value is 2^32. (Optional, defaults to 7200);
* -TCP  - Specifiy to create TCP mapping instead of UDP (Optional);
* -GP xxxxx  - Port that NAT-PMP-capable gateway is listening on. (Optional, defaults to 5351);
* -GW xxx.xxx.xxx.xxx  - IPv4 of the GateWay (Optional, defaults to IPv4 address of the gateway on the interface);
* -DM xx:xx:xx:xx:xx:xx  - Destination (target's) MAC (Optional, but host must be reachable with NetBios);
* -GM xx:xx:xx:xx:xx:xx  - Gateway MAC (Optional, but gateway must be reachable with NetBios);

# Q&A
* Q: Can it create TCP mappings? A: Yes, it can.
* Q: I need both TCP&UDP, do I need to run it twice? A: Yes, TCP+UDP implementation will be added later.

# Libraries in use
* Win32, iphlpapi ;
* PcapPlusPlus and all of it's dependencies https://github.com/seladb/PcapPlusPlus ;

# Compatibility with multihomed networks
Both UPNP and NAT-PMP aren't designed to work under such conditions. You can still manually specify IP addresses of gateways and create mapping on each gateway, however.
