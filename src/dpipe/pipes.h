#pragma once

#include <Windows.h>
#include <string>
#include <mutex>

extern bool shutdownRemotePipeThreads;

extern std::string inputBuffer;
extern std::mutex inputBufferMtx;
extern std::thread* exec_thread;

BOOL handle_input_string(char** input, size_t* inputLen);
void handle_output_string(char* string, DWORD dwRead);
void write_to_input(std::string input);
int create_remote_output_pipe(std::string hostname);
int create_remote_input_pipe(std::string hostname);
void shutdown_pipes(std::string hostname);
