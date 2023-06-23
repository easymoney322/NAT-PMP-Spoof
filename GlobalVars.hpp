#ifndef GlobalVars
#define GlobalVars
#pragma once
#include <iostream>
#include <string>
#include <vector>
#include <packet.h>
extern bool istcp;
extern bool both;

extern std::string SMAC; //Our MAC (Optional, might be reqired to determine output interface if target is in a different subnet)
extern std::string DMAC; //MAC of device we will be impersonating (Optional)
extern std::string GWMAC; //Gateway MAC (Optional)
extern std::string DADDR; //IPv4 of device we will be impersonating 
extern std::string DGWAY; //IPv4 of gateway device (Optional)
extern uint_fast8_t progmode ;
extern uint_fast16_t gwlistenerport; //Port that NAT-PMP-capable gateway listening to
extern uint_fast16_t internalport;
extern uint_fast16_t externalport;
extern uint_fast32_t mappinglifetime; //Recommended to be 2 hrs (https://datatracker.ietf.org/doc/html/rfc6886)
extern std::vector <pcpp::Packet> SentPackets;

extern struct WinDev {
    std::string ipaddr{ "" }; //IPv4 address of an interface as as tring
    std::string gwayip{ "" }; //DGWAY as a string
    std::vector<uint_fast8_t> macaddrvec; //MAC address of an interface
    std::uint_fast32_t bitaddr{ 0 }; //IPv4 address as a 32bit unsigned integer
    std::uint_fast32_t bitmask{ 0 }; //Net mask as a 32bit unsigned integer
    std::uint_fast32_t wildcardmask{ 0 }; //bit-flip version of bitmask
    std::uint_fast32_t netaddress{ 0 }; //IPv4 address of a network (e.g. 192.168.1.0)
    std::uint_fast32_t broadcastaddress{ 0 }; //IPv4 broadcast address of that network (e.g. 192.168.1.255)
    unsigned long interfaceindex{ 0 }; //So we can check if interface already added and update it accordingly. Index is the same as the one you get with "netsh interface ipv4 show interfaces" command.
};
extern std::vector<WinDev> DEVS;
#endif