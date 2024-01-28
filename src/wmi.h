#pragma once

#include <string>

void wmi_netstat(std::string host, std::string domain, std::string user, std::string pwd);
void wmi_exec(std::string host, std::string domain, std::string user, std::string pwd, std::string cmd);
void wmi_ps(std::string host, std::string domain, std::string user, std::string pwd);
