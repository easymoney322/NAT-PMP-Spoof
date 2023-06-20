# NAT-PMP-Spoof
Spoofing NAT-PMP on Windows. There were no good NAT-PMP apps for Windows so I made one.

# What it does
The project allows user to craft a packet and send it to Gateway for port mapping. It supposed to work with UPNP as well, and works with miniupnpd.

User may specify any IPv4 address, as opposed to natpmpc. Since it will impersonate specified host, the host either need to be reachable with NetBIOS, or hosts's addresses need to be passed to the program.

This allows you to make a port mapping even with  secure mode enabled natpmp-d, which is helpful when you have no access to the host for who you want to create the port mapping.

If you run the program behind NAT or from different subnet, the work depends on your gateway device. Please test it with low mapping lifetime first, as you might be unable to remove the mapping, as there is no such functionality yet.

# Requirements
* x64 Windows 
* wpcap (can be installed with npcap https://npcap.com/ )


# Usage
* -help  - Shows this message;
* -PH xxxxx  -  Port on the host, who we are impersonating (REQUIRED);
* -DA xxx.xxx.xxx.xxx  - IPv4 of host we will be impersonating (REQUIRED);
* -PO xxxxx  - Port on the GateWay (Optional, defaults to specified host port)" << std::endl //If not passed, will be the same as port on the host;
* -T xxxxxxxxx  - Time of the binding in seconds: 0 for infinite, the max value is 2^32. (Optional, defaults to 7200);
* -TCP  - Specifiy to create TCP mapping instead of UDP (Optional);
* -BOTH  - Specify to create both TCP and UDP mappings (Optional);
* -GP xxxxx  - Port that NAT-PMP-capable gateway is listening on. (Optional, defaults to 5351);
* -GW xxx.xxx.xxx.xxx  - IPv4 of the GateWay (Optional, defaults to IPv4 address of the gateway on the interface);
* -DM xx:xx:xx:xx:xx:xx  - Destination (target's) MAC (Optional, but host must be reachable with NetBios);
* -GM xx:xx:xx:xx:xx:xx  - Gateway MAC (Optional, but gateway must be reachable with NetBios);
* -SM xx:xx:xx:xx:xx:xx - Out source MAC (Optional, if host is in the same subnet as the target);


# Q&A
* Q: Can it create TCP mappings? 

Yes, it can.
* Q: Will it work if secure_mode is set to "yes" on my gateway device?

Yes, that's the whole point of this project.
* Q: How can I be sure that the mapping is really created?

There is no feature for checking right now, but you can use UPnP Wizard (may not show mapping lifetime correctly) or you can check NAT-PMP leases on your GateWay (e.g. /tmp/upnp.leases)
* Q: How can I remove mapping?

There is no such feature right now, but you can still do it with UPnP Wizard or upnp.leases file.
* Q: Windows Defender quarantines the program with "This program is dangerous and executes commands from an attacker"...

You can check binary file with Virus Total (http://virustotal.com) or manually review the code and compile it. There is no RCE, and the only shadow thing in an entire project - is spoofing.

# Libraries in use
* Win32, iphlpapi ;
* PcapPlusPlus and all of it's dependencies https://github.com/seladb/PcapPlusPlus ;

# Compatibility with multihomed networks
Both UPNP and NAT-PMP aren't designed to work under such conditions. You can still manually specify IP addresses of gateways and create mapping on each gateway, however.
