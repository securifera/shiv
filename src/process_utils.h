#pragma once

#include <string>

void CreateProcessWithPipeComm(std::string cmd);
static void CreateChildProcess(std::string command, PROCESS_INFORMATION* piProcInfo);