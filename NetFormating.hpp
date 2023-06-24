#pragma once
#include <bitset>
#include <iomanip>
#include <iostream>
#include <format>
#include <string>
#include <vector>
#include <algorithm>
#include <PayloadLayer.h>
#include <chrono>
#include <Packet.h>

char DetermineDelimiter(std::string inputstring, uint_fast8_t expectedblocksize);
int MakeMeIpv4(uint_fast32_t input, unsigned int& a, unsigned int& b, unsigned int& c, unsigned int& d);
uint_fast16_t portcheck(const std::string inputstring, const char* whos);
uint_fast32_t GetMappingLifetimeFromPacket(pcpp::Packet lspacket);
uint_fast32_t SchizoConverter(std::string inputstring);

void PrintIPV4(const char* msg, uint_fast32_t input);
void PrintIPV4(const char* msg, uint_fast32_t input); //Not an endianness independent code
void PrintIPV42(const char* msg, uint_fast32_t input);
void PrintIPV43(const char* msg, uint_fast32_t input);
void PrintMacFromVec(const std::vector <uint_fast8_t> inputvec);

std::vector<std::string> split(std::string s, const char delimiter);
std::vector<uint_fast8_t> payloadtovec(pcpp::PayloadLayer payload);

std::string MacVecToStringWithDelimiters(std::vector <uint_fast8_t> inputvec, const char delimiter);
std::string VecToString(std::vector <uint_fast8_t> inputvec);
std::string VecToStringWithDelimiters(std::vector <std::string> inputvec, const char delimiter);
std::string VecToStringWithDelimiters(std::vector <uint_fast8_t> inputvec, const char delimiter);


const static auto MVTSWD = MacVecToStringWithDelimiters;