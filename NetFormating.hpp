#pragma once
#include <iostream>
#include <iomanip>
#include <format>
#include <string>
#include <vector>
#include <bitset>

int MakeMeIpv4(uint32_t input, unsigned int& a, unsigned int& b, unsigned int& c, unsigned int& d);
uint32_t SchizoConverter(std::string inputstring);

void PrintIPV4(const char* msg, uint32_t input);
void PrintIPV4(const char* msg, uint32_t input); //Not an endianness independent code
void PrintIPV42(const char* msg, uint32_t input);
void PrintIPV43(const char* msg, uint32_t input);
void PrintMacFromVec(const std::vector <uint8_t> inputvec);

std::vector<std::string> split(std::string s, const char delimiter);

std::string MacVecToStringWithDelimiters(std::vector <uint8_t> inputvec, const char delimiter);
std::string VecToString(std::vector <uint8_t> inputvec);
std::string VecToStringWithDelimiters(std::vector <uint8_t> inputvec, const char delimiter);



const auto VTSWD = VecToStringWithDelimiters;
const static auto MVTSWD = MacVecToStringWithDelimiters;