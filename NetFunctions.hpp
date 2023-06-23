#pragma once
#include "NetFormating.hpp"
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
#include "GlobalVars.hpp"
WinDev FindAppropriateDevice(const std::vector <WinDev> inputvec, const std::string DestIp);
WinDev FindAppropriateDeviceByMac(const std::vector <WinDev> inputvec, const std::string SMAC);
void getDevices();
void sendarp(WinDev localstruct, std::string destinationv4, std::vector <uint_fast8_t>& inputvec); //[IN] WinDev, [IN] std::string IPV4, [OUT] std::vector uint_fast8_t
uint_fast8_t ComparePayloads(pcpp::PayloadLayer payload1, pcpp::PayloadLayer payload2); //0 = equal, 1 = not equal, 2 = len(p1)>len(p2), 3 = len(p1)<len(p2)
uint_fast8_t DestroyAllMappings(std::string dsDMAC, std::string dsGWMAC, std::string dsDADDR, WinDev dsOut, bool tcp, std::string dsDGWAY, uint_fast16_t dsGWlistenport);
uint_fast8_t DestroySingleMapping(std::string dsDMAC, std::string dsGWMAC, std::string dsDADDR, WinDev dsOut, bool tcp, uint_fast16_t dsinternalport, std::string dsDGWAY, uint_fast16_t dsGWlistenport);
uint_fast8_t sendspoof(std::string lsDMAC, std::string lsGWMAC, std::string lsDADDR, WinDev Out, bool lstcp, uint_fast16_t lsinternalport, uint_fast16_t lsexternalport, std::string lsDGWAY, uint_fast16_t lsGWlistenport, uint_fast32_t mappingtime);
uint_fast8_t PrintPayloadFromPacket(pcpp::Packet packet);
uint_fast8_t RemoveCreatedMappings(std::vector <pcpp::Packet>& packetvector, std::string lsDMAC, std::string lsGWMAC, std::string lsDADDR, WinDev lsOut, std::string lsDGWAY, uint_fast16_t lsGWlistenport); //Removes all mappings created in the session
