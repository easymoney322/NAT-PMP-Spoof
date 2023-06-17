#ifndef GlobalVars
#define GlobalVars
#pragma once
#include <iostream>
#include <string>
#include <vector>
extern bool istcp;
extern struct WinDev;
extern std::vector<WinDev> DEVS;
extern std::string SMAC; //Our MAC (Optional, might be reqired to determine output interface if target is in a different subnet)
extern std::string DMAC; //MAC of device we will be impersonating (Optional)
extern std::string GWMAC; //Gateway MAC (Optional)
extern std::string DADDR; //IPv4 of device we will be impersonating 
extern std::string DGWAY; //IPv4 of gateway device (Optional)
extern uint16_t gwlistenerport; //Port that NAT-PMP-capable gateway listening to
extern uint16_t internalport;
extern uint16_t externalport;
extern uint32_t mappinglifetime; //Recommended to be 2 hrs (https://datatracker.ietf.org/doc/html/rfc6886)

extern struct WinDev {
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
#endif