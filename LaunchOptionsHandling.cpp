#include "LaunchOptionsHandling.hpp"

std::vector<std::string> launcharguments;
int LaunchOptionsProcessing(int localargc, char* localargv[])
{
    if (21 < localargc)  // 8*2 + TCP + 1 + 1
    {
        throw std::runtime_error("too many input parameters!");
    }


    if (5 > localargc)   // (PH + DA)*2 + 1
    {
        std::cerr << "Not enough arguments!" << std::endl;
        std::cerr << "Usage: " << std::endl
            << "-help  - Shows this message." << std::endl
            << "-PH xxxxx  -  Port on the host, who we are impersonating (REQUIRED)" << std::endl
            << "-DA xxx.xxx.xxx.xxx  - IPv4 of host we will be impersonating (REQUIRED)" << std::endl
            << "-PO xxxxx  - Port on the GateWay (Optional, defaults to specified host port)" << std::endl //If not passed, will be the same as port on the host
            << "-T xxxxxxxxx  - Time of the binding in seconds: 0 for infinite, the max value is 2^32. (Optional, defaults to 7200)" << std::endl
            << "-TCP  - Specifiy to create TCP mapping instead of UDP (Optional)" << std::endl
            << "-GP xxxxx  - Port that NAT-PMP-capable gateway is listening on. (Optional, defaults to 5351)" << std::endl
            << "-GW xxx.xxx.xxx.xxx  - IPv4 of the GateWay (Optional, defaults to IPv4 address of the gateway on the interface)" << std::endl
            << "-DM xx:xx:xx:xx:xx:xx  - Destination (target's) MAC (Optional, but host must be reachable with NetBios)" << std::endl
            << "-GM xx:xx:xx:xx:xx:xx  - Gateway MAC (Optional, but gateway must be reachable with NetBios)" << std::endl
            << "-SM xx:xx:xx:xx:xx:xx - Out source MAC !CASE SENSITIVE, USE LOWER CASE! (Optional, if host in the same subnet as the target)" << std::endl;
        return EXIT_FAILURE;
    }
    

    launcharguments = std::vector<std::string>(localargv, localargv + localargc);


    if ((has_option(launcharguments, "-help") || has_option(launcharguments, "--help")))
    {
        std::cerr << "Usage: " << std::endl
            << "-help  - Shows this message." << std::endl
            << "-PH xxxxx  -  Port on the host, who we are impersonating (REQUIRED)" << std::endl
            << "-DA xxx.xxx.xxx.xxx  - IPv4 of host we will be impersonating (REQUIRED)" << std::endl
            << "-PO xxxxx  - Port on the GateWay (Optional, defaults to specified host port)" << std::endl //If not passed, will be the same as port on the host
            << "-T xxxxxxxxx  - Time of the binding in seconds: 0 for infinite, the max value is 2^32. (Optional, defaults to 7200)" << std::endl
            << "-TCP  - Specifiy to create TCP mapping instead of UDP (Optional)" << std::endl
            << "-GP xxxxx  - Port that NAT-PMP-capable gateway is listening on. (Optional, defaults to 5351)" << std::endl
            << "-GW xxx.xxx.xxx.xxx  - IPv4 of the GateWay (Optional, defaults to IPv4 address of the gateway on the interface)" << std::endl
            << "-DM xx:xx:xx:xx:xx:xx  - Destination (target's) MAC !CASE SENSITIVE, USE LOWER CASE! (Optional, but host must be reachable with NetBios)" << std::endl
            << "-GM xx:xx:xx:xx:xx:xx  - Gateway MAC !CASE SENSITIVE, USE LOWER CASE!(Optional, but gateway must be reachable with NetBios)" << std::endl
            << "-SM xx:xx:xx:xx:xx:xx - Out source MAC !CASE SENSITIVE, USE LOWER CASE! (Optional, if host in the same subnet as the target)" << std::endl;
        return EXIT_FAILURE;
    }




    if (true == has_option(launcharguments, "-PH")) //Host port argument handling
    {
        std::string HostPortString = get_option(launcharguments, "-PH");
        uint16_t retloc = portcheck(HostPortString, "host");
        if (0 != retloc)
        {
            internalport = retloc;
        }
        else
        {
            return EXIT_FAILURE;
        }
    }
    else
    {
        std::cerr << "Missing port argument. Please specify host's port with \"-PH\"." << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "Host port is " << internalport << ". ";


    if (true == has_option(launcharguments, "-PO")) //Gateway binding port argument handling 
    {
        std::string ExternalPortString = get_option(launcharguments, "-PO");
        uint16_t retloc = portcheck(ExternalPortString, "gateway");
        if (0 != retloc)
        {
            externalport = retloc;
        }
        else
        {
            return EXIT_FAILURE;
        }
    }
    else
    {
        std::cout << std::endl << "Gateway port wasn't specified. Using the same port...  ";
        externalport = internalport;
    }
    std::cout << "Gateway port for binding is " << externalport << ";" << std::endl;


    istcp = has_option(launcharguments, "-TCP"); // TCP/UDP argument handling


    if (true == has_option(launcharguments, "-DA")) // Destination IPv4 argument handling
    {
        std::string dastring = get_option(launcharguments, "-DA");
        pcpp::IPv4Address testv4(dastring);
        if (true == testv4.isValid())
        {
            DADDR = dastring;
        }
        else
        {
            DADDR.clear();
            std::cerr << "Specified IPv4 address of the target isn't valid." << std::endl;
            return EXIT_FAILURE;
        }
    }
    else
    {
        std::cerr << "Missing IPv4 address of the target, that is required. Please specify target address with \"-DA\"." << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "Target's address is " << DADDR << "; " << std::endl;


    if (true == has_option(launcharguments, "-DM")) //Destination MAC argument handling
    {
        mac_testerproto("-DM", DMAC);
        std::cout << "Destination MAC is set to " << DMAC << std::endl;
    }
    else
    {
        DMAC.clear();
    }


    if (true == has_option(launcharguments, "-GM")) //Gateway MAC argument handling
    {
        mac_testerproto("-GM", GWMAC);
        std::cout << "GateWay MAC is set to " << GWMAC << std::endl;
    }
    else
    {
        GWMAC.clear();
    }


    if (true == has_option(launcharguments, "-SM")) //Gateway MAC argument handling
    {
        mac_testerproto("-SM", SMAC);
        std::cout << "Source MAC is set to " << SMAC << std::endl;
    }
    else
    {
        SMAC.clear();
    }


    if (true == has_option(launcharguments, "-GW")) //Gateway IPv4 argument handling
    {
        std::string gwastring = get_option(launcharguments, "-GW");
        pcpp::IPv4Address testv4(gwastring);
        if (true == testv4.isValid())
        {
            DGWAY = gwastring;
        }
        else
        {
            DGWAY.clear();
            std::cerr << "Specified IPv4 address of the gateway isn't valid." << std::endl;
            return EXIT_FAILURE;
        }
    }



    return 0;
}

std::string get_option(const std::vector<std::string>& args, const std::string& option_name)
{
    for (auto it = args.begin(), end = args.end(); it != end; ++it)
    {
        if (option_name == *it)
        {
            if ((it + 1) != end)
            {
                return *(it + 1);
            }
        }
    }
    return "";
}


bool has_option(const std::vector<std::string>& args, const std::string& option_name)
{
    for (auto it = args.begin(), end = args.end(); it != end; ++it)
    {
        if (option_name == *it)
        {
            return true;
        }
    }
    return false;
}

void mac_testerproto(const char * launchparam, std::string &globalvar)
{
    std::string premac = get_option(launcharguments, launchparam);
    //!! THERE'S NEED TO BE MAC VALIDNESS CHECK BUT THERE IS NONE
    globalvar = premac;
}