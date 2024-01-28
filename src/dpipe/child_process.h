#pragma once

#include <string>
#include <vector>

extern bool shutdownPipes;
extern bool processExited;
extern HANDLE stopEvent;

void CreateProcessWithPipeComm(std::string cmd);
void ExecuteSC(PVOID pBuffer);
void CreateChildProcess(std::string cmd, PROCESS_INFORMATION*);
DWORD WINAPI WriteToPipe(LPVOID);
DWORD WINAPI ReadFromPipe(LPVOID);

std::string get_hostname();
void cleanup();
