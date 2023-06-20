
#include "GlobalVars.hpp"

std::vector<WinDev> DEVS; //Vector, containing all our interfaces
std::string SMAC{ "" }; //Our MAC 
std::string DMAC{ "" }; //MAC of device we will be impersonating (Optional)
std::string GWMAC{ "" }; //Gateway MAC (Optional)
std::string DADDR{ "" }; //IPv4 of device we will be impersonating 
std::string DGWAY{ "" }; //IPv4 of gateway device (Optional)
bool istcp = false;
bool both = false;
uint16_t gwlistenerport = 5351; //Default port
uint16_t internalport = 1025;
uint16_t externalport = 1025;
uint32_t mappinglifetime = 7200; //Recommended to be 2 hrs (https://datatracker.ietf.org/doc/html/rfc6886)