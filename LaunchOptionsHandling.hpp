#pragma once
#include <iostream>
#include <string>
#include <vector>
#include "GlobalVars.hpp"
#include "NetFormating.hpp"
#include "NetFunctions.hpp"

extern std::vector<std::string> launcharguments;

bool has_option(const std::vector<std::string>& args, const std::string& option_name);
int LaunchOptionsProcessing(int localargc, char* localargv[]);
std::string get_option(const std::vector<std::string>& args, const std::string& option_name);
void mac_testerproto(const char* launchparam, std::string globalvar);