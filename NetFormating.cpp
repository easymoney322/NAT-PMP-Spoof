#include "NetFormating.hpp"

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

void PrintMacFromVec(const std::vector <uint8_t> inputvec)
{
    unsigned int k = (inputvec.size() - 1);
    for (unsigned int i = 0; i < k; i++)
    {
        std::cout << std::setfill('0') << std::setw(2) << std::hex << (int)inputvec.at(i) << ":";
    }
    std::cout << std::setfill('0') << std::setw(2) << std::hex << (int)inputvec.at(k) << std::endl;
}