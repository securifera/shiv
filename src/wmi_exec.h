#pragma once

#include <string>

//BOOL wmi_exec_cmd(std::string host, std::string cmd);
//BOOL wmi_exec_cmd2(std::string host, std::string cmd);
void wmi_exec_cmd2(std::string host, std::string domain, std::string user, std::string pwd, std::string cmd);
