# NAT-PMP-Spoof
Spoofing NAT-PMP on Windows. There were no good NAT-PMP apps for Windows, so I made one.

# What it does
The project allows user to craft a packet and send it to Gateway for port mapping. It supposed to work with UPNP as well, and works with miniupnpd.

User may specify any IPv4 address, as opposed to natpmpc. Since it will impersonate specified host, the host either need to be reachable with NetBIOS, or hosts's addresses need to be passed to the program.

This allows you to make a port mapping even with  secure mode enabled natpmp-d, which is helpful when you have no access to the host for who you want to create the port mapping.

If you run the program behind NAT or from different subnet, the work depends on your gateway device. Please test it with low mapping lifetime first, as you might be unable to remove the mapping, as there is no such functionality yet.

# Requirements
* x64 Windows
* wpcap (can be installed with [npcap](https://npcap.com/)
* MSVC Runtime

# Usage
* -help  - Shows this message;
* -DA xxx.xxx.xxx.xxx  - IPv4 of host we will be impersonating **(REQUIRED)**;
* -PH xxxxx  -  Port on the host, who we are impersonating **(REQUIRED)**;
* -PO xxxxx  - External port on the Gateway (Optional, defaults to specified host port);
* -T xxxxxxxxx  - Time of the binding in seconds: 0 for infinite, the max value is 2^32. (Optional, defaults to 7200);
* -TCP  - Specifiy to create TCP mapping instead of UDP (Optional);
* -BOTH  - Specify to create both TCP and UDP mappings (Optional);
* -GP xxxxx  - Port that NAT-PMP-capable gateway is listening on. (Optional, defaults to 5351);
* -GW xxx.xxx.xxx.xxx  - IPv4 of the NAT-PMP Gateway (Optional, defaults to IPv4 address of the gateway on the interface);
* -SA xxx.xxx.xxx.xxx  - IPv4 of output interfiace (Optional);
* -DM xx:xx:xx:xx:xx:xx  - Destination (target's) MAC address (Optional, but host must be reachable with NetBios);
* -GM xx:xx:xx:xx:xx:xx  - MAC address of Gateway in the broadcast domain, that is the next hop (Optional in single broadcast domain, but gateway must be reachable with NetBios);
* -SM xx:xx:xx:xx:xx:xx - MAC address of output interface (Optional, if host is in the same subnet as the target);
* -TS  - Sleep time in seconds for hold mode loop. (Optional, defaults to 5 sec);
## [Modes] (Optional)
* -A (Default)  - Single Mapping creating mode;
* -H  - Hold mode;
* -R  - Single mapping removal mode;
* -RALL  - All mappings removal mode;
* If no mode argument is provided, mapping creation mode (-A) will be used instead;

# Examples

## Creating mappings
In most of the cases these will be enough:
* UDP:
`NAT-PMP-Spoofer.exe -DA 192.168.1.228 -PH 9999`
This command will try to create UDP mapping on found gateway for host (.1.228), forwarding **UDP** traffic to host's port 9999 from the same UDP port on the Gateway. 

* TCP:
`NAT-PMP-Spoofer.exe -DA 192.168.1.228 -PH 80 -PO 8080 -TCP`
This command will try to create TCP mapping on found gateway for host (.1.228), forwarding **TCP** traffic from port 8080 on the gateway to port 80 on host. 

Both commands will create mappings that will last 7200 seconds (2 hours). Please note that according to [RFC 6886](https://datatracker.ietf.org/doc/html/rfc6886/), "The NAT gateway MAY reduce the lifetime from what the client requested". Also, according to this RFC, some NAT-PMP-capable gateways may reject requests if time isn't set to zero.

Both commands requrie additional data that will be fetched with mechanisms such as ARP-requests or win32 API. 
If, for some reason, the required data cannot be fetched, user must provide it manually by launch arguments:
`NAT-PMP-Spoofer.exe -DA 192.168.1.228  -DM b1:6b:00:b5:ba:be  -PH 80 -PO 8080  -TCP  -GW 192.168.1.1  -GM c1:5c:0d:06:1e  -SM ba:be:de:fe:c8:ed -T 0`

Providing additional data with launch arguments increases speed of the programm, while also reducing network presence.

## Creating and auto-renewing mappings
Mappings will be renewed halfway through, as RFC proposes. Due to busy waiting, it will load the CPU.

`NAT-PMP-Spoofer.exe -H -DA 192.168.1.228 -PH 9999 -T 1234`

## Removing mappings
* Removing UDP:
`NAT-PMP-Spoofer.exe -R -DA 192.168.1.228 -PH 80`

* Removing TCP+UDP:
`NAT-PMP-Spoofer.exe -R -DA 192.168.1.228 -PH 80 -BOTH`

* Removing All NAT-PMP mappings that are associated with the host:
`NAT-PMP-Spoofer.exe -RALL -DA 192.168.1.228`


# Q&A
* Q: Can it create TCP mappings? 

Yes, it can.
* Q: Will it work if secure_mode is set to "yes" on my gateway device?

Yes, that's the whole point of this project.
* Q: How can I be sure that the mapping is really created?

There is no feature for checking right now, but you can use UPnP Wizard (may not show mapping lifetime correctly) or you can check NAT-PMP leases on your GateWay (e.g. /tmp/upnp.leases)

* Q: Windows Defender quarantines the program with "This program is dangerous and executes commands from an attacker"...

You can check binary file with Virus Total (http://virustotal.com) or manually review the code and compile it. There is no RCE, and the only shadow thing in an entire project - is spoofing.

# Libraries in use
* Win32, iphlpapi ;
* PcapPlusPlus and all of it's dependencies https://github.com/seladb/PcapPlusPlus ;

# Compatibility with multihomed networks
Both UPNP and NAT-PMP aren't designed to work under such conditions. You can still manually specify IP addresses of gateways and create mapping on each gateway, however.

# Upcoming features
- [ ] Viewing mappings;
- [X] Auto-prolongation for the hold mode;
- [ ] Multi-threading for the hold mode;
- [ ] Topology images for examples;
- [ ] Endianness independent code for ARM-based Windows systems;
- [ ] Configuration via files;
- [ ] Static builds;
- [ ] CI/CD;