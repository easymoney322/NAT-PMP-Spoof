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
void getDevices();
void sendarp(WinDev localstruct, std::string destinationv4, std::vector <uint8_t>& inputvec); //[IN] WinDev, [IN] std::string IPV4, [OUT] std::vector uint8_t
uint8_t sendspoof(std::string lsDMAC, std::string lsGWMAC, std::string lsDADDR, WinDev Out, bool lstcp, uint16_t lsinternalport, uint16_t lsexternalport, uint16_t lsGWlistenport, uint32_t mappingtime);
