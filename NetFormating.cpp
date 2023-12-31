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
        std::transform(substr.begin(), substr.end(), substr.begin(), [](unsigned char c) { return std::tolower(c); });
        res.push_back(substr);
    }
    res.push_back(s.substr(pos_start));
   
    return res;
}

std::vector<uint_fast8_t> payloadtovec(pcpp::PayloadLayer payload)
{
    std::vector <uint_fast8_t> retval;
    uint8_t* addr = payload.getPayload();
    for (unsigned int i = 0; i < payload.getPayloadLen(); i++)
    {
        retval.push_back( *(addr + i) );
    }
    return retval;
}


void PrintIPV4(const char* msg, uint_fast32_t input) //Not an endianness independent code
{
    unsigned int d = input & 0xFF;
    unsigned int c = (input >> 8) & 0xFF;
    unsigned int b = (input >> 16) & 0xFF;
    unsigned int a = (input >> 24) & 0xFF;
    std::cout << msg << std::dec << a << "." << b << "." << c << "." << d << std::endl;
}

int MakeMeIpv4(uint_fast32_t input, unsigned int& a, unsigned int& b, unsigned int& c, unsigned int& d)
{
    uint_fast8_t* bytes = reinterpret_cast<uint_fast8_t*>(&input);
    d = static_cast <int>(bytes[0]);
    c = static_cast <int>(bytes[1]);
    b = static_cast <int>(bytes[2]);
    a = static_cast <int>(bytes[3]);
    return 0;
}

void PrintIPV42(const char* msg, uint_fast32_t input)
{
    uint_fast8_t* bytes = reinterpret_cast<uint_fast8_t*>(&input);
    unsigned int d = static_cast <int>(bytes[0]);
    unsigned int c = static_cast <int>(bytes[1]);
    unsigned int b = static_cast <int>(bytes[2]);
    unsigned int a = static_cast <int>(bytes[3]);
    std::cout << msg << std::dec << a << "." << b << "." << c << "." << d << std::endl;
}

void PrintIPV43(const char* msg, uint_fast32_t input)
{
    uint_fast8_t* cde = (uint_fast8_t*)(&(input));
    unsigned int d = *cde;
    unsigned int c = *(cde + 1);
    unsigned int b = *(cde + 2);
    unsigned int a = *(cde + 3);
    std::cout << msg << std::dec << a << "." << b << "." << c << "." << d << std::endl;
}

uint_fast32_t SchizoConverter(std::string inputstring)
{
    std::vector<std::string> v = split(inputstring, '.');
    uint_fast32_t retval = 0;
    for (int l = 0; l < v.size(); l++)
    {
        retval = (retval << 8) | std::stoi(v[l]);
    }
    return retval;
}

std::string VecToString(std::vector <uint_fast8_t> inputvec)
{
    std::string retval;
    for (int i = 0; i < inputvec.size(); i++)
    {
        retval += inputvec.at(i);

    }
    std::transform(retval.begin(), retval.end(), retval.begin(), [](unsigned char c) { return std::tolower(c); });
    return retval;
}

std::string VecToStringWithDelimiters(std::vector <uint_fast8_t> inputvec, const char delimiter)
{
    std::string retval;
    for (int i = 0; i < (inputvec.size() - 1); i++)
    {
        retval += std::to_string(inputvec.at(i));
        retval += delimiter;
    }
    retval += std::to_string(inputvec.at(inputvec.size() - 1));
    std::transform(retval.begin(), retval.end(), retval.begin(), [](unsigned char c) { return std::tolower(c); });
    return retval;
}

std::string VecToStringWithDelimiters(std::vector <std::string> inputvec, const char delimiter)
{
    std::string retval;
    for (int i = 0; i < (inputvec.size() - 1); i++)
    {
        retval += (inputvec.at(i));
        retval += delimiter;
    }
    retval += (inputvec.at(inputvec.size() - 1));
    std::transform(retval.begin(), retval.end(), retval.begin(), [](unsigned char c) { return std::tolower(c); });
    return retval;
}

std::string MacVecToStringWithDelimiters(std::vector <uint_fast8_t> inputvec, const char delimiter)
{
    std::string retval;
    for (int i = 0; i < (inputvec.size() - 1); i++)
    {
        retval += std::format("{:02x}", inputvec.at(i));
        retval += delimiter;
    }
    retval += std::format("{:02x}", inputvec.at(inputvec.size() - 1));
    return retval;
}

void PrintMacFromVec(const std::vector <uint_fast8_t> inputvec)
{
    unsigned int k = (inputvec.size() - 1);
    for (unsigned int i = 0; i < k; i++)
    {
        std::cout << std::setfill('0') << std::setw(2) << std::hex << (int)inputvec.at(i) << ":";
    }
    std::cout << std::setfill('0') << std::setw(2) << std::hex << (int)inputvec.at(k) << std::endl;
}

uint_fast16_t portcheck(const std::string inputstring, const char* whos)
{
    int64_t portinput;
    if (!inputstring.empty())
    {
        try
        {
            portinput = std::stol(inputstring); //Does it handle exceptions?
        }
        catch (const std::invalid_argument& ia)
        {
            std::cerr << "Invalid argument: " << ia.what() << " when processing port number for " << whos << std::endl;
            return 0;
        }
        if (portinput < 1025)
        {
            std::cerr << "Warning: Ports in range 0-1024 are privileged ports, and such binding request might be denied by the GateWay." << std::endl;
        }
        if (!((portinput > 0) && (portinput < 65536)))
        {
            std::cerr << "Invalid " << whos << " port number!" << std::endl;
            return 0;
        }
        return portinput;
    }
    else
    {
        std::string outtext = whos;
        outtext[0] = toupper(outtext[0]);
        std::cerr << outtext << " port launch argument is specified, but the value for port is missing!" << std::endl;
        return 0;
    }
}

char DetermineDelimiter(std::string inputstring, uint_fast8_t expectedblocksize)
{
    uint_fast8_t incr = expectedblocksize + 1;

    unsigned int a = inputstring.size() / incr; //Delimiters count
    unsigned int b = (inputstring.size() + 1) / incr; //Blocks count
    unsigned int c = (b * 2) + a;
    char g = '\0';
    if (inputstring.size() == c)
    {
        g = inputstring.at(expectedblocksize);
        bool test = true;
        for (int z = 2; z < inputstring.size(); z += 3)
        {
            if (inputstring.at(z) != g)
            {
                test = false;
                std::cerr << "Inconsistent Delimiters or size!" << std::endl;
                break;
            }
        }
        if (true == test)
        {
            return g;
        }
    }
    g = '\0';
    return g;
}

uint_fast32_t GetMappingLifetimeFromPacket(pcpp::Packet lspacket)
{
    uint8_t* ppayload = lspacket.getLayerOfType<pcpp::PayloadLayer>()->getPayload();
    uint_fast32_t* packetlifetime = (uint_fast32_t*)&ppayload[8];
    uint_fast32_t hostorder = ntohl(*packetlifetime);
    return hostorder;
}