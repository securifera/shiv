/**
  BSD 3-Clause License

  Copyright (c) 2019, Securifera, Inc. All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

  * Redistributions of source code must retain the above copyright notice, this
	list of conditions and the following disclaimer.

  * Redistributions in binary form must reproduce the above copyright notice,
	this list of conditions and the following disclaimer in the documentation
	and/or other materials provided with the distribution.

  * Neither the name of the copyright holder nor the names of its
	contributors may be used to endorse or promote products derived from
	this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <windows.h> 
#include <stdio.h> 
#include <string>
#include <thread>
#include <iostream>
#include <vector>
#include <io.h>
#include <Fcntl.h>

#include "child_process.h"
#include "pipes.h"
#include "..\debug.h"

#define STDIN_FILENO 0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2

std::thread* stdin_pipe_thread = nullptr;
std::thread* stdout_pipe_thread = nullptr;

void start_threads()
{
	if ( exec_thread!= nullptr || stdin_pipe_thread != nullptr || stdout_pipe_thread != nullptr) {
		DebugFprintf(outlogfile, PRINT_INFO1, "[-] Threads already started.\n");
	}
	else {

		//Redirect STDOUT and STDERR
		//HANDLE new_stdout = CreateFileA("C:\\redirect_log.txt", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
		//SetStdHandle(STD_OUTPUT_HANDLE, new_stdout);
		//SetStdHandle(STD_ERROR_HANDLE, new_stdout);
		//setvbuf(stdout, NULL, _IONBF, 0);

		//Get hostname
		std::string hostname = get_hostname();

		shutdownPipes = false;
		shutdownRemotePipeThreads = false;
		stdin_pipe_thread = new std::thread(create_remote_input_pipe, hostname);
		stdout_pipe_thread = new std::thread(create_remote_output_pipe, hostname);
	}
}

void stop_threads()
{
	shutdownPipes = true;
	if (exec_thread != nullptr) {
		if (stopEvent) {
			SetEvent(stopEvent);
		}
	}
	cleanup();

	//Get hostname
	std::string hostname = get_hostname();

	shutdownRemotePipeThreads = true;
	shutdown_pipes(hostname);
	if (stdin_pipe_thread != nullptr) {
		stdin_pipe_thread->join();
		delete stdin_pipe_thread;
		stdin_pipe_thread = nullptr;
	}

	if (stdout_pipe_thread != nullptr) {
		stdout_pipe_thread->join();
		delete stdout_pipe_thread;
		stdout_pipe_thread = nullptr;
	}

}

void npsrv_entry()
{
	//Open debug file and flush
	fopen_s(&outlogfile, "C:\\debug.txt", "a+");
	setvbuf(outlogfile, NULL, _IONBF, 0);

	DebugFprintf(outlogfile, PRINT_ERROR, "[+] Starting threads.\n");
	start_threads();
	DebugFprintf(outlogfile, PRINT_ERROR, "[+] Threads started.\n");
}

void npsrv_exit()
{
	DebugFprintf(outlogfile, PRINT_ERROR, "[+] Stopping threads and exiting.\n");
	stop_threads();
}


