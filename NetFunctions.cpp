#include "NetFunctions.hpp"
#pragma warning(disable : 4996)


uint_fast8_t sendspoof(std::string lsDMAC, std::string lsGWMAC, std::string lsDADDR, WinDev Out, bool lstcp, uint_fast16_t lsinternalport, uint_fast16_t lsexternalport, std::string lsDGWAY, uint_fast16_t lsGWlistenport, uint_fast32_t mappingtime)
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

    uint_fast8_t* lsbuffer = (uint_fast8_t*)calloc(12, sizeof(uint_fast8_t)); //4 bytes * 3 rows = 12
    if (lsbuffer)
    {
        lsbuffer[0] = 0; //Version

        uint_fast8_t mappingopcode = 1;
        if (lstcp)
            mappingopcode = 2;
        lsbuffer[1] = (uint_fast8_t(mappingopcode)); //1 for UDP and 2 for TCP. 

        //2nd and 3rd bytes are reserved
        uint_fast8_t* ptr16t8 = (uint_fast8_t*)(&(lsinternalport)); //Internal (host) port
        lsbuffer[4] = *(ptr16t8 + 1); //BE,MSB
        lsbuffer[5] = *ptr16t8;       //LSB

        ptr16t8 = (uint_fast8_t*)(&(lsexternalport)); //External (GW) port
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
        std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)lsbuffer[11] << ";" << std::endl;
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
        SendPacketWrap(newPacket, Out);
        free(lsbuffer);
        return 322;
    }
    std::cerr << "Wasn't able to allocate memory. Aborting..." << std::endl;
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
                std::vector<uint_fast8_t> hwaddr;
                if ('0' != pAdapterInfo->IpAddressList.IpAddress.String[0])
                {
                    for (unsigned int i = 0; i < pAdapterInfo->AddressLength; i++)
                    {
                        hwaddr.push_back((uint_fast8_t)pAdapterInfo->Address[i]);
                    }

                    unsigned long localinterfaceindex = pAdapterInfo->Index;
                    uint_fast32_t bitmask = SchizoConverter(pAdapterInfo->IpAddressList.IpMask.String);
                    uint_fast32_t bitipaddr = SchizoConverter(pAdapterInfo->IpAddressList.IpAddress.String);
                    uint_fast32_t netaddr = bitipaddr & bitmask;        //Calculate network address
                    uint_fast32_t wildcardmask = ~bitmask;
                    uint_fast32_t broadcastaddr = netaddr | wildcardmask;   //Calculate network broadcast address

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


void sendarp(const WinDev localstruct, const std::string destinationv4, std::vector <uint_fast8_t>& inputvec) //[IN] WinDev, [IN] std::string IPV4, [OUT] std::vector uint_fast8_t
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
                inputvec.push_back((uint_fast8_t)bPhysAddr[i]);
                std::cout << std::setfill('0') << std::setw(2) << std::hex << (int)bPhysAddr[i] << ":";
            }
            inputvec.push_back((uint_fast8_t)bPhysAddr[id]);
            std::cout << std::setfill('0') << std::setw(2) << std::hex << (int)bPhysAddr[id] <<  ";" << std::endl;
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


WinDev FindDeviceBySourceIP(const std::vector <WinDev> inputvec, const std::string SourceIp)
{
    uint_fast32_t reformatedSourceIP = SchizoConverter(SourceIp);
    for (int i = 0; i < inputvec.size(); i++)
    {
        if (reformatedSourceIP == inputvec[i].bitaddr)
        {
            std::cout << "Found appropriate interface (by source IPv4) at index=" << inputvec[i].interfaceindex << ";" << std::endl;
            return inputvec[i];
        }
    }
    std::cout << "Wasn't able to find output device from the same network." << std::endl;
    return { "", "", {NULL},0,0,0,0,0 }; //We probably should use default GW if interface wasn't found
}


WinDev FindAppropriateDevice(const std::vector <WinDev> inputvec, const std::string DestIp)
{
    uint_fast32_t reformatedDestIP = SchizoConverter(DestIp);
    for (int i = 0; i < inputvec.size(); i++)
    {
        if ((inputvec[i].bitmask & reformatedDestIP) == inputvec[i].netaddress)
        {
            std::cout << "Found appropriate interface (by network address) at index=" << inputvec[i].interfaceindex << ";" << std::endl;
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



uint_fast8_t ComparePayloads(pcpp::PayloadLayer payload1, pcpp::PayloadLayer payload2)     //0 = equal, 1 = not equal, 2 = len(p1)>len(p2), 3 = len(p1)<len(p2)
{
    uint_fast64_t len1 = payload1.getPayloadLen();
    uint_fast64_t len2 = payload2.getPayloadLen();
    if (len1 == len2)
    {
        std::vector <uint8_t> vec1 = payloadtovec(payload1);
        std::vector <uint8_t> vec2 = payloadtovec(payload2);
        bool vecequality = true;
        for (unsigned int i = 0; i < len1; i++)
        {
            if (vec1.at(i) != vec2.at(i))
            {
                vecequality = false;
                break;
            }
        }
        if (true == vecequality)
        {
            return 0;
        }
        return 1;
    }
    else
    {
        if (len1 > len2)
        {
            return 2;
        }
        return 3;
    }
}

uint_fast8_t DestroySingleMapping(std::string dsDMAC, std::string dsGWMAC, std::string dsDADDR, WinDev dsOut, bool tcp, uint_fast16_t dsinternalport, std::string dsDGWAY, uint_fast16_t dsGWlistenport)
{
    //A client requests explicit deletion of a mapping by sending a message to the NAT gateway requesting the mapping, with the Requested Lifetime in Seconds set to zero. 
    //The Suggested External Port MUST be set to zero by the client on sending, and MUST be ignored by the gateway on reception.
    return sendspoof(dsDMAC, dsGWMAC, dsDADDR, dsOut, tcp, dsinternalport, (uint_fast16_t) 0, dsDGWAY, dsGWlistenport, (uint_fast32_t)0);
}

uint_fast8_t DestroyAllMappings(std::string dsDMAC, std::string dsGWMAC, std::string dsDADDR, WinDev dsOut, bool tcp, std::string dsDGWAY, uint_fast16_t dsGWlistenport)
{
    //A client can request the explicit deletion of all its UDP or TCP mappings by sending the same deletion request to the NAT gateway with the external port, internal port, and lifetime set to zero.
    return sendspoof(dsDMAC, dsGWMAC, dsDADDR, dsOut, tcp, (uint_fast16_t)0, (uint_fast16_t)0, dsDGWAY, dsGWlistenport, (uint_fast32_t)0);
}


uint_fast8_t RemoveCreatedMappings(std::vector <pcpp::Packet> &packetvector, WinDev lsOut)
{
    pcpp::IPv4Address testv4(lsOut.ipaddr);
    if (true == testv4.isValid())
    {
        pcpp::PcapLiveDevice* dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(testv4);
        if (nullptr == dev)
        {
            std::cerr << "Couldn't find interface by provided IP address or name" << std::endl;
            return 201;
        }
        if (!dev->open())
        {
            std::cerr << "Couldn't open the device." << std::endl;
            return 202;
        }
        else
        {
            for (int i = 0; i < packetvector.size(); i++)
            {
                uint8_t* pltest = packetvector.at(i).getLayerOfType<pcpp::PayloadLayer>()->getPayload();
                unsigned int z = SentPackets.at(i).getLastLayer()->getDataLen();
               // uint8_t* ar = new uint8_t[z];
                pltest[6] = 0; //ExPort MSB
                pltest[7] = 0; //LSB

                pltest[8] = 0; //Lifetime MSB
                pltest[9] = 0;
                pltest[10] = 0;
                pltest[11] = 0; //LSB
            
                packetvector.at(i).computeCalculateFields();
                dev->sendPacket(&packetvector.at(i));
            }
            ProlongationList.clear(); //We must add IDs to packets in the vectors, and remove them accordingly with vector::erase 
            return 0;
        }
    }
    std::cerr << "Host address didn't pass the validation check. Aborting..." << std::endl;
    return 322;
}

uint_fast8_t PrintPayloadFromPacket(pcpp::Packet packet)
{
    uint8_t* ppayload = packet.getLayerOfType<pcpp::PayloadLayer>()->getPayload();
    uint8_t dlen = packet.getLayerOfType<pcpp::PayloadLayer>()->getPayloadLen();
    std::cout << std::endl << "Payload print:";
    for (int i = 0; i < dlen; i++)
    {
        std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)ppayload[i] << "-";
    }
    return 0;
}


std::chrono::time_point <std::chrono::system_clock> CreateTimepointOfNextUpdate(pcpp::PayloadLayer payload)
{
    uint8_t* pdata = payload.getPayload();
    uint_fast32_t* packetlifetime = (uint_fast32_t*)&pdata[8];
    uint_fast32_t hostorder = ntohl(*packetlifetime);
    hostorder /= 2;  //Time till refresh in seconds
    std::chrono::time_point <std::chrono::system_clock> systemtime = std::chrono::system_clock::now();
    std::chrono::time_point <std::chrono::system_clock> timeofrefresh = systemtime + std::chrono::seconds(hostorder);
    const std::time_t datetimesyst = std::chrono::system_clock::to_time_t(systemtime);
    const std::time_t datetimerefr = std::chrono::system_clock::to_time_t(timeofrefresh);
    return timeofrefresh;
}


ProtoPort GetProtoAndPortFromPayloadLayer(pcpp::PayloadLayer lspayload)
{
    uint8_t* pdata = lspayload.getPayload();
    uint_fast8_t opmode = pdata[1];
    std::string retstr;
    uint_fast16_t retint = 0;
    uint_fast16_t retext = 0;
    uint_fast32_t maptime = 1;
    if (1 == opmode)
    {
        retstr = "UDP";
    }
    if (2 == opmode)
    {
        retstr = "TCP";
    }
    if ( retstr.empty() )
    {
        std::cerr << "Error occured during protocol processing" << std::endl;
    }

    uint_fast16_t* portnumint = (uint_fast16_t*)&pdata[4]; //4,5 = INT
    retint = ntohs(*portnumint);
    uint_fast16_t* portnumext = (uint_fast16_t*)&pdata[6]; //6,7 = EXT
    retext = ntohs(*portnumext);
    uint_fast32_t* maplifetime = (uint_fast32_t*)&pdata[8];
    maptime = ntohl(*maplifetime);
    std::string Updstr = "Updated mapping for " + retstr + '-' + std::to_string(retint) + '-' + std::to_string(retext) + '-' + std::to_string(maptime) + '.';
    return { retstr,retint, retext, maptime, Updstr };
}


ProtoPort GetProtoAndPortFromPacket(pcpp::Packet packet)
{
    pcpp::PayloadLayer * ppayload = packet.getLayerOfType<pcpp::PayloadLayer>();
    ProtoPort retval = GetProtoAndPortFromPayloadLayer(*ppayload);
    return retval;
}


uint_fast8_t WatchList()
{
    std::chrono::time_point <std::chrono::system_clock> systemtime;
    while (0 < ProlongationList.size() )
    {
        systemtime = std::chrono::system_clock::now();
        for (int it = 0; it < ProlongationList.size(); it++)
        {
            if (ProlongationList.at(it).chronotimepoint <= systemtime)
            {
                uint8_t res = SendPacketWrap(ProlongationList.at(it).Packet, OutputInterface);
                if (0 != res)
                {
                    std::cerr << "An error occured when tried to update mapping time!" << std::endl;
                }
            }

        }
        return 0;
    }
    if (0 == ProlongationList.size())
    {
        return 1;
    }

   
}


uint_fast8_t SendPacketWrap(pcpp::Packet &lspacket, WinDev lsOut)
{
    pcpp::IPv4Address testv4(lsOut.ipaddr);
    if (true == testv4.isValid())
    {
        pcpp::PcapLiveDevice* dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(testv4);
        if (nullptr == dev)
        {
            std::cerr << "Couldn't find interface by provided IP address or name" << std::endl;
            return 201;
        }
        if (!dev->open())
        {
            std::cerr << "Couldn't open the device." << std::endl;
            return 202;
        }
        else
        {
            dev->sendPacket(&lspacket);
            if ((1 == progmode) and (0 != externalport)) //Caching mappings is only needed in Hold mode
            {
                bool alreadyexists = false;
                pcpp::PayloadLayer lspayload = *(lspacket.getLayerOfType<pcpp::PayloadLayer>());
                for (unsigned int sp = 0; sp < SentPackets.size(); sp++)
                {
                    if (0 == ComparePayloads(*(SentPackets.at(sp).getLayerOfType<pcpp::PayloadLayer>()), lspayload))
                    {
                        alreadyexists = true;
                        SentPackets.at(sp) = lspacket;
                    }
                }
                if (false == alreadyexists)
                {
                    SentPackets.push_back(lspacket);
                }
                uint_fast32_t mappingtime = GetMappingLifetimeFromPacket(lspacket);
                if (0 != mappingtime)
                {
                    alreadyexists = false;
                    for (unsigned int sp = 0; sp < ProlongationList.size(); sp++)
                    {
                        if (0 == ComparePayloads(*(ProlongationList.at(sp).Packet.getLayerOfType<pcpp::PayloadLayer>()), lspayload))
                        {
                            alreadyexists = true;
                            std::chrono::time_point <std::chrono::system_clock> UpdateTime = CreateTimepointOfNextUpdate(lspayload);
                            ProlongationList.at(sp).chronotimepoint = UpdateTime;
                            std::time_t datetimerefr = std::chrono::system_clock::to_time_t(UpdateTime);
                            std::string str1 = ProlongationList.at(sp).ProtocolAndPort.UpdateText;
                            std::string str2 = "Next update for this mapping will be at " + (std::string) std::ctime(&datetimerefr);
                            uint_fast64_t outwidth;
                            if (str1.size() > str2.size())
                            {
                                outwidth = str1.size();
                            }
                            else
                            {
                                outwidth = str2.size();
                            }
                            std::cout << std::setw(outwidth) << std::setfill('-') << " " << std::endl;
                            std::cout << str1 << std::endl;
                            std::cout << str2;
                            std::cout << std::setw(outwidth) << std::setfill('-') << " " << std::endl;
                        }
                    }
                    if (false == alreadyexists)
                    {
                        ProtoPort lsportstruc = GetProtoAndPortFromPayloadLayer(lspayload);
                        ProlongationList.push_back({ lspacket ,CreateTimepointOfNextUpdate(lspayload),lsportstruc});
                    }
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(250)); //250ms delay to assure correct processing in series of requests
            return 0;
        }
    }
    std::cerr << "Host address didn't pass the validation check. Aborting..." << std::endl;
    return 322;

}