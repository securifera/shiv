#pragma once

#include <string>

BOOL winrm_exec_cmd(std::string host, unsigned short port, std::string cmd, std::string user, std::string passwd);