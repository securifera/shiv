#pragma once
#include <string>
#include <vector>

void connect_named_pipes(std::string ip, std::string hostname, std::string cmd, std::vector<unsigned char>* sc_bytes);
BOOL chunk_pipe_write(HANDLE hPipe, std::vector<unsigned char>* pipe_data);
VOID InitSecurityAttributes(PSECURITY_ATTRIBUTES pAttributes);