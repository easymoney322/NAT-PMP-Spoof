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

int main()
{

    DADDR = "192.168.1.234";//Testing purpose

    if (DMAC.empty())  //If we don't pass destination MAC, we need to get it with ARP
    {
        getDevices(); //Interfaces will be added to DEVS vector.
        WinDev OutputInterface = FindAppropriateDevice(DEVS, DADDR); //Will return WinDev object with interface from the same network
        SMAC = MacVecToStringWithDelimiters(OutputInterface.macaddrvec, ':');
        std::vector <uint8_t> targetmac;
        std::cout << std::endl << "Destination MAC not found, making an ARP request..." << std::endl;
        sendarp(OutputInterface, DADDR, targetmac);
        DMAC = MVTSWD(targetmac, ':');
        if (DGWAY.empty())
        {
            DGWAY = OutputInterface.gwayip;
            if (GWMAC.empty())
            {
                std::vector <uint8_t> gwaymacvec;
                std::cout << std::endl << "Gateway MAC not found, making an ARP request..." << std::endl;
                sendarp(OutputInterface, DGWAY, gwaymacvec);
                std::cout << std::endl;
                GWMAC = MacVecToStringWithDelimiters(gwaymacvec, ':');
            }
        }
        uint8_t pretval = sendspoof(DMAC, GWMAC, DADDR, OutputInterface, istcp, internalport, externalport, gwlistenerport, mappinglifetime);
        if (0 == pretval)
            std::cout << "Nat-PMP request sent" << std::endl;
    }
    if (DGWAY.empty())
    {
        getDevices(); //Interfaces will be added to DEVS vector.
        WinDev OutputInterface = FindAppropriateDevice(DEVS, DADDR);
        DGWAY = OutputInterface.gwayip;
        if (GWMAC.empty())
        {
            std::vector <uint8_t> gwaymacvec;
            std::cout << std::endl << "Gateway MAC not found, making an ARP request..." << std::endl;
            sendarp(OutputInterface, DGWAY, gwaymacvec);
            std::cout << std::endl;
            GWMAC = VecToString(gwaymacvec);
        }
        uint8_t pretval = sendspoof(DMAC, GWMAC, DADDR, OutputInterface, istcp, internalport, externalport, gwlistenerport, mappinglifetime);
        if (0 == pretval)
            std::cout << "Nat-PMP request sent" << std::endl;
    }
    system("PAUSE");
}
