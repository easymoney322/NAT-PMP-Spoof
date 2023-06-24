#include "OtherFunctions.hpp"

BOOL WINAPI CtrlHandler(DWORD fdwCtrlType)
{
    switch (fdwCtrlType)
    {
        // Handle the CTRL-C signal.
    case CTRL_C_EVENT: 
    {
        std::cout << "Received CTRL-C signal. Removing mappings..." << std::endl;
        Beep(750, 300);
        uint_fast8_t retval = RemoveCreatedMappings(SentPackets, OutputInterface);
        if (0 == retval)
        {
            std::cout << "All mapping removal request are sent." << std::endl;

        }
        else
        {
            std::cerr << "An error occured during mapping removal process" << std::endl;

        }
        return TRUE;
    }
        // CTRL-CLOSE: confirm that the user wants to exit.
    case CTRL_CLOSE_EVENT:
    {
        Beep(600, 200);
        std::cout << "Received Ctrl-Close signal." << std::endl;
        uint_fast8_t retval = RemoveCreatedMappings(SentPackets, OutputInterface);
        if (0 == retval)
        {
            std::cout << "All mapping removal request are sent." << std::endl;

        }
        else
        {
            std::cerr << "An error occured during mapping removal process" << std::endl;
        }
        return TRUE;
    }
        // Pass other signals to the next handler.
    case CTRL_BREAK_EVENT:
    {
        Beep(900, 200);
        std::cout << "Recieved Ctrl-Break signal." << std::endl;
        uint_fast8_t retval = RemoveCreatedMappings(SentPackets, OutputInterface);
        if (0 == retval)
        {
            std::cout << "All mapping removal request are sent." << std::endl;

        }
        else
        {
            std::cerr << "An error occured during mapping removal process" << std::endl;

        }
        return FALSE;
    }
    case CTRL_LOGOFF_EVENT:
    {
        Beep(1000, 200);
        std::cout << "Recieved Ctrl-Logoff signal." << std::endl;
        uint_fast8_t retval = RemoveCreatedMappings(SentPackets, OutputInterface);
        if (0 == retval)
        {
            std::cout << "All mapping removal request are sent." << std::endl;

        }
        else
        {
            std::cerr << "An error occured during mapping removal process" << std::endl;

        }
        return FALSE;
    }
    case CTRL_SHUTDOWN_EVENT:
    {
        Beep(750, 500);
        std::cout << "Received Ctrl-Shutdown signal." << std::endl;
        uint_fast8_t retval = RemoveCreatedMappings(SentPackets, OutputInterface);
        if (0 == retval)
        {
            std::cout << "All mapping removal request are sent." << std::endl;

        }
        else
        {
            std::cerr << "An error occured during mapping removal process" << std::endl;

        }
        return FALSE;
    }
    default:
        return FALSE;
    }
}

