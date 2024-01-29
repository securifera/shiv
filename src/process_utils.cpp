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


#define _CRT_SECURE_NO_DEPRECATE 1
#include <windows.h>
#include <stdio.h>
#include "process_utils.h"
#include "debug.h"

#define BUFSIZE 4096

static HANDLE hChildStdinRd, hChildStdinWr, hChildStdoutRd, hChildStdoutWr, hStdout;

DWORD WINAPI WriteToPipe(LPVOID);
DWORD WINAPI ReadFromPipe(LPVOID);
bool processExited = false;

void CreateProcessWithPipeComm(std::string command)
{
	PROCESS_INFORMATION piProcInfo;
	SECURITY_ATTRIBUTES saAttr;
	DWORD dwThreadId[2];
	HANDLE hThread[2];
	processExited = false;

	// Set the bInheritHandle flag so pipe handles are inherited.
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;

	// Get the handle to the current STDOUT.
	hStdout = GetStdHandle(STD_OUTPUT_HANDLE);

	// Create a pipe for the child process's STDOUT.
	if (!CreatePipe(&hChildStdoutRd, &hChildStdoutWr, &saAttr, 0))
	{
		DebugFprintf(outlogfile, PRINT_ERROR, "[-] Stdout pipe creation failed\n");
		return;
	}

	// Ensure the read handle to the pipe for STDOUT is not inherited.
	SetHandleInformation(hChildStdoutRd, HANDLE_FLAG_INHERIT, 0);

	// Create a pipe for the child process's STDIN.
	if (!CreatePipe(&hChildStdinRd, &hChildStdinWr, &saAttr, 0))
	{
		DebugFprintf(outlogfile, PRINT_ERROR, "[-] Stdin pipe creation failed\n");
		return;
	}

	// Ensure the write handle to the pipe for STDIN is not inherited.
	SetHandleInformation(hChildStdinWr, HANDLE_FLAG_INHERIT, 0);

	// Now create the child process.
	CreateChildProcess(command, &piProcInfo);

	hThread[0] = CreateThread(
		NULL,              // default security attributes
		0,                 // use default stack size
		ReadFromPipe,        // thread function
		NULL,             // argument to thread function
		0,                 // use default creation flags
		&dwThreadId[0]);   // returns the thread identifier

	//hThread[1] = CreateThread(
	//	NULL,              // default security attributes
	//	0,                 // use default stack size
	//	WriteToPipe,        // thread function
	//	NULL,             // argument to thread function
	//	0,                 // use default creation flags
	//	&dwThreadId[1]);   // returns the thread identifier

	WaitForSingleObject(piProcInfo.hProcess, INFINITE);
	processExited = true;

	//Get exit code
	DWORD exit_code;
	GetExitCodeProcess(piProcInfo.hProcess, &exit_code);

	DebugFprintf(outlogfile, PRINT_INFO1, "[-] Process exited. Code: %d\n", exit_code);

	// when process finished notify pipe thread to finish
	WaitForMultipleObjects(1, hThread, TRUE, INFINITE);
	//DebugFprintf(outlogfile, PRINT_INFO1, "[-] Pipe threads exited\n");
}

void CreateChildProcess(std::string command, PROCESS_INFORMATION* piProcInfo)
{
	STARTUPINFO siStartInfo;
	BOOL bFuncRetn = FALSE;

	// Set up members of the PROCESS_INFORMATION structure.
	ZeroMemory(piProcInfo, sizeof(PROCESS_INFORMATION));

	// Set up members of the STARTUPINFO structure.
	ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
	siStartInfo.cb = sizeof(STARTUPINFO);
	siStartInfo.hStdError = hChildStdoutWr;
	siStartInfo.hStdOutput = hChildStdoutWr;
	siStartInfo.hStdInput = 0;
	siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

	bFuncRetn = CreateProcess(NULL, (LPSTR)command.c_str(), NULL, NULL, TRUE, 0, NULL, NULL, &siStartInfo, piProcInfo);
	if (bFuncRetn == 0)
		DebugFprintf(outlogfile, PRINT_ERROR, "[-] Failed to create new process: %d\n", GetLastError());
}

BOOL output_counted_string(char* string, DWORD dwRead)
{
	DWORD dwWritten;

	dwWritten = (DWORD)fwrite(string, sizeof(char), dwRead, stdout);
	fflush(stdout);
	return dwWritten;

}

BOOL read_counted_input(char* string, int string_size, DWORD* dwRead)
{
	char* ret_value;

	ret_value = gets_s(string, string_size);
	*dwRead = (DWORD)strlen(string) + 1;
	return (BOOL)(ret_value > 0);

}

//static DWORD WINAPI WriteToPipe(LPVOID p)
//{
//	DWORD dwRead, dwWritten;
//	CHAR chBuf[BUFSIZE];
//
//	for (;;)
//	{
//		if (!read_counted_input(chBuf, BUFSIZE, &dwRead))
//			break;
//
//		chBuf[dwRead - 1] = '\n';
//		if (!WriteFile(hChildStdinWr, chBuf, dwRead,
//			&dwWritten, NULL))
//			break;
//
//		//Break out of thread if process exited
//		if (processExited)
//			break;
//	}
//
//	DebugFprintf(outlogfile, PRINT_INFO1, "[*] Write Pipe Closed.");
//
//	return 0;
//}

static DWORD WINAPI ReadFromPipe(LPVOID p)
{
	DWORD dwRead;
	CHAR chBuf[BUFSIZE];

	for (;;)
	{
		DWORD bytesRead = 0, bytesAvail = 0, bytesLeft = 0;
		BOOL ret = PeekNamedPipe(hChildStdoutRd, NULL, 0, &bytesRead, &bytesAvail, &bytesLeft);
		if (ret == TRUE && bytesAvail > 0) {
			if (!ReadFile(hChildStdoutRd, chBuf, BUFSIZE, &dwRead, NULL) || dwRead == 0) {
				break;
			}

			if (dwRead > 0) {
				//DebugFprintf(outlogfile, PRINT_INFO3, "[*] Bytes Read: %d\n", dwRead);
				if (!output_counted_string(chBuf, dwRead))
					break;

				// clear read buffer
				memset(chBuf, 0, sizeof(chBuf));
				dwRead = 0;
			}
		}
		else {
			//Break out of thread if process exited
			if (processExited)
				break;

			Sleep(50);
		}

	}

	//DebugFprintf(outlogfile, PRINT_INFO1, "[*] Read Pipe Closed.");

	return 0;
}
