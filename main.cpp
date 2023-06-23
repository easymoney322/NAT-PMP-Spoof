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
#include "LaunchOptionsHandling.hpp"
#pragma comment(lib, "wpcap" )
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "IPHLPAPI.lib")
#pragma comment(lib, "Packet.lib")
#pragma comment(lib, "Common++.lib")
#pragma comment(lib, "Packet++.lib")
#pragma comment(lib, "Pcap++.lib")

WinDev OutputInterface;
int main(int argc, char* argv[])
{
    if (EXIT_FAILURE == LaunchOptionsProcessing(argc, argv)  ) //Handling of launch arguments
    {
        return EXIT_FAILURE;
    }


    getDevices(); //Interfaces will be added to DEVS vector.
    OutputInterface = FindAppropriateDevice(DEVS, DADDR); //Will return WinDev object with interface from the same network


    if (DGWAY.empty())
    {
        DGWAY = OutputInterface.gwayip;
    }


    if ("" == OutputInterface.ipaddr )
    {
        if (!SMAC.empty())
        {
            OutputInterface = FindAppropriateDeviceByMac(DEVS, SMAC);
            if ("" == OutputInterface.ipaddr)
            {
                std::cerr << "Wasn't able to determine output interface." << std::endl;
                return EXIT_FAILURE;
            }
        }
        else 
        {
            std::cerr << "Source MAC wasn't specified, and no interface with matching subnet was found. Aborting..." << std::endl;
            return EXIT_FAILURE;
        }
    }
    std::cout << "Output IPv4 is " << OutputInterface.ipaddr << std::endl;


    if (DMAC.empty())  //If we don't pass destination MAC, we need to get it with ARP
    {
        SMAC = MacVecToStringWithDelimiters(OutputInterface.macaddrvec, ':');
        std::vector <uint_fast8_t> targetmac;
        std::cout << std::endl << "Destination MAC address not found, making an ARP request..." << std::endl;
        sendarp(OutputInterface, DADDR, targetmac);
        DMAC = MVTSWD(targetmac, ':');
    }


    if (DGWAY.empty())
    {
        DGWAY = OutputInterface.gwayip;
        if (GWMAC.empty())
        {
            std::vector <uint_fast8_t> gwaymacvec;
            std::cout << std::endl << "Gateway MAC address not found, making an ARP request..." << std::endl;
            sendarp(OutputInterface, DGWAY, gwaymacvec);
            if (!gwaymacvec.empty())
            {
                GWMAC = VecToString(gwaymacvec);
            }
        }
    }
    else 
    {
        if (GWMAC.empty())
        {
            std::vector <uint_fast8_t> gwaymacvec;
            std::cout << std::endl << "Gateway MAC address not found, making an ARP request..." << std::endl;
            sendarp(OutputInterface, DGWAY, gwaymacvec);
            if (!gwaymacvec.empty())
            {
                GWMAC = VecToString(gwaymacvec);
            }
        }
    }


    if (!GWMAC.empty())
    {

        uint_fast8_t switchretval = 2;
        switch (progmode)
        {
            case 1:
                //if (SetConsoleCtrlHandler(CtrlHandler, TRUE))
                //{
                //
                //}
                break;
            case 2:
            {
                if (true == both)
                {
                    switchretval = DestroySingleMapping(DMAC, GWMAC, DADDR, OutputInterface, false, internalport, DGWAY, gwlistenerport);
                    if (0 == switchretval)
                    {
                        std::cout << "Sent Nat-PMP request for destroying UDP mapping" << std::endl;
                    }
                    istcp = true;
                    switchretval = DestroySingleMapping(DMAC, GWMAC, DADDR, OutputInterface, istcp, internalport, DGWAY, gwlistenerport);
                    if (0 == switchretval)
                    {
                        std::cout << "Sent Nat-PMP request for destroying TCP mapping" << std::endl;
                    }
                    break;
                }
                else
                {
                    switchretval = DestroySingleMapping(DMAC, GWMAC, DADDR, OutputInterface, istcp, internalport, DGWAY, gwlistenerport);
                    if (0 == switchretval)
                    {
                        std::cout << "Sent Nat-PMP request for destroying mapping" << std::endl;
                    }
                    break;
                }
            }
            case 3:
            {
                switchretval = DestroyAllMappings(DMAC, GWMAC, DADDR, OutputInterface, istcp, DGWAY, gwlistenerport);
                if (0 == switchretval)
                {
                    std::cout << "Sent Nat-PMP request for destroying all associated mappings" << std::endl;
                }
                break;
            }
            case 4:
                //View mode
                //for checking existing mappings
                break;
            default:
            {
                if (true == both)
                {
                    switchretval = sendspoof(DMAC, GWMAC, DADDR, OutputInterface, false, internalport, externalport, DGWAY, gwlistenerport, mappinglifetime);
                    if (0 == switchretval)
                    {
                        std::cout << "Nat-PMP request sent for UDP" << std::endl;
                    }
                    istcp = true;
                    switchretval = sendspoof(DMAC, GWMAC, DADDR, OutputInterface, istcp, internalport, externalport, DGWAY, gwlistenerport, mappinglifetime);
                    if (0 == switchretval)
                    {
                        std::cout << "Nat-PMP request sent for TCP" << std::endl;
                    }
                    return 0;
                }
                else
                {
                    switchretval = sendspoof(DMAC, GWMAC, DADDR, OutputInterface, istcp, internalport, externalport, DGWAY, gwlistenerport, mappinglifetime);
                    if (0 == switchretval)
                    {
                        std::cout << "Nat-PMP request sent" << std::endl;
                    }
                }
                break;
            }
        }
    }


    system("PAUSE");
    return 0;
}
