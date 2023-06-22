#include "NetFunctions.hpp"

#define VERBOSE
uint8_t sendspoof(std::string lsDMAC, std::string lsGWMAC, std::string lsDADDR, WinDev Out, bool lstcp, uint16_t lsinternalport, uint16_t lsexternalport, std::string lsDGWAY, uint16_t lsGWlistenport, uint32_t mappingtime)
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

        std::cout << std::endl << "Packet's payload is set to: ";
        for (int z = 0; z < 11; z++)
        {
            std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)lsbuffer[z] << '-';
        }
        std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)lsbuffer[11] << std::endl;
        std::cout << std::dec;

        pcpp::EthLayer newEthernetLayer(lsDMAC, lsGWMAC);
        pcpp::IPv4Layer newIPLayer(pcpp::IPv4Address(lsDADDR), pcpp::IPv4Address((std::string) lsDGWAY));
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
            {
                std::cout << "Couldn't find interface by provided IP address or name" << std::endl;
            }
            if (!dev->open())
            {
                std::cout << "!Couldn't open the device." << std::endl;
            }
            else
            {
                std::cout << "Trying to send packet for ";
                if (true == lstcp)
                {
                    std::cout << "TCP" << std::endl;
                }
                else
                {
                    std::cout << "UDP" << std::endl;
                }
                int sentCount = dev->sendPacket(&newPacket);
                std::this_thread::sleep_for(std::chrono::milliseconds(250)); //250ms delay to assure correct processing in series of requests
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
        inputvec.clear();
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

WinDev FindAppropriateDevice(const std::vector <WinDev> inputvec, const std::string DestIp)
{
    uint32_t reformatedDestIP = SchizoConverter(DestIp);
    for (int i = 0; i < inputvec.size(); i++)
    {
        if ((inputvec[i].bitmask & reformatedDestIP) == inputvec[i].netaddress)
        {
            std::cout << "Found appropriate interface at index=" << inputvec[i].interfaceindex << std::endl;
            return inputvec[i];
        }
    }
    std::cout << "Wasn't able to find output device from the same network." << std::endl;
    return { "", "", {NULL},0,0,0,0,0 }; //We probably should use default GW if interface wasn't found
}

WinDev FindAppropriateDeviceByMac(const std::vector <WinDev> inputvec, const std::string SMAC)
{
    std::string intmac{ "" };
    for (int i = 0; i < inputvec.size(); i++)
    {
        intmac.clear();
        intmac = MacVecToStringWithDelimiters(inputvec[i].macaddrvec, ':');
        if (SMAC == intmac)
        {
            std::cout << std::endl << "Found appropriate interface at index=" << inputvec[i].interfaceindex << std::endl;
            return inputvec[i];
        }
    }
    std::cerr << "Wasn't able to find an output device with matching Source MAC. Check if passed MAC is all lowercase, and if there is any typo" << std::endl;
    return { "", "", {NULL},0,0,0,0,0 }; //We probably should use default GW if interface wasn't found
}