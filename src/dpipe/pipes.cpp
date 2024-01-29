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

#include <stdio.h>
#include <strsafe.h>  //StringCchCopyA
#include <string>
#include <mutex>

#include "pipes.h"
#include "child_process.h"
#include "..\debug.h"
#include "..\pipe_data.h"
#include "..\named_pipe_utils.h"

#define PIPE_BUFFER_SIZE 0x10000

DWORD WINAPI InstanceThread(LPVOID);
DWORD WINAPI RemoteOutputHandler(LPVOID lpvParam);
DWORD WINAPI RemoteInputHandler(LPVOID lpvParam);
VOID GetAnswerToRequest(LPTSTR, LPTSTR, LPDWORD);

std::string inputBuffer;
std::mutex inputBufferMtx;
std::thread* exec_thread = NULL;


std::vector<unsigned char> outputBuffer;
std::mutex outputBufferMtx;
bool shutdownRemotePipeThreads = false;

HANDLE hRemoteInputPipe = INVALID_HANDLE_VALUE;
HANDLE hRemoteOutputPipe = INVALID_HANDLE_VALUE;

BOOL handle_input_string(char** input, size_t* inputLen)
{
	//input validation
    if (!input || !inputLen)
        return FALSE;

    inputBufferMtx.lock();

    if (inputBuffer.size() > 0) {
        (*input) = (char*)calloc(inputBuffer.size() + 1, sizeof(char));
        memcpy((*input), inputBuffer.c_str(), inputBuffer.size());
        (*inputLen) = inputBuffer.size();
    }
    inputBuffer.clear();
    inputBufferMtx.unlock();

    return TRUE;
}

void handle_output_string(char* output_string, DWORD dwRead)
{

    outputBufferMtx.lock();
    outputBuffer.insert(outputBuffer.end(), output_string, output_string + dwRead);
    outputBufferMtx.unlock();

    DebugFprintf(outlogfile, PRINT_INFO1, "%s", output_string);

}

void write_to_input(std::string input)
{
    inputBufferMtx.lock();
    inputBuffer = input;
    inputBufferMtx.unlock();
}

void shutdown_pipes(std::string hostname)
{
    std::string stdout_pipe_name = "\\\\.\\pipe\\";
    stdout_pipe_name.append(hostname);
    stdout_pipe_name.append("O");

    std::string stdin_pipe_name = "\\\\.\\pipe\\";
    stdin_pipe_name.append(hostname);
    stdin_pipe_name.append("I");

    //force the blocking pipe connection function to continue with a quick connection
    HANDLE hPipe = CreateFileA(stdout_pipe_name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe != INVALID_HANDLE_VALUE)
        CloseHandle(hPipe);

    //force the blocking pipe connection function to continue with a quick connection
    hPipe = CreateFileA(stdin_pipe_name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe != INVALID_HANDLE_VALUE)
        CloseHandle(hPipe);

    Sleep(500);

    if (hRemoteInputPipe != INVALID_HANDLE_VALUE) {
        DebugFprintf(outlogfile, PRINT_INFO1, "[+] Disconnecting remote input pipe.\n");
        DisconnectNamedPipe(hRemoteInputPipe);
        CloseHandle(hRemoteInputPipe);
        hRemoteInputPipe = INVALID_HANDLE_VALUE;
    }

    if (hRemoteOutputPipe != INVALID_HANDLE_VALUE) {
        DebugFprintf(outlogfile, PRINT_INFO1, "[+] Disconnecting remote output pipe.\n");
        DisconnectNamedPipe(hRemoteOutputPipe);
        CloseHandle(hRemoteOutputPipe);
        hRemoteOutputPipe = INVALID_HANDLE_VALUE;
    }
}

int create_remote_output_pipe(std::string hostname)
{
    BOOL   fConnected = FALSE;
    DWORD  dwThreadId = 0;
    HANDLE hThread = NULL;
    SECURITY_ATTRIBUTES sa = { 0 };

    std::string stdout_pipe_name = "\\\\.\\pipe\\";
    stdout_pipe_name.append(hostname);
    stdout_pipe_name.append("O");

    DebugFprintf(outlogfile, PRINT_INFO2, "[+] Creating stdout named pipe %s\n", stdout_pipe_name.c_str());     
    InitSecurityAttributes(&sa);
        
    hRemoteOutputPipe = CreateNamedPipeA(
        stdout_pipe_name.c_str(), // pipe name 
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE,
        PIPE_UNLIMITED_INSTANCES, // max. instances  
        PIPE_BUFFER_SIZE,                  // output buffer size 
        PIPE_BUFFER_SIZE,                  // input buffer size 
        0,                        // client time-out 
        &sa);                    // default security attribute

    if (hRemoteOutputPipe == INVALID_HANDLE_VALUE) {
        DebugFprintf(outlogfile, PRINT_ERROR, "[-] CreateNamedPipe failed, GLE=%d.\n", GetLastError());
        return -1;
    }
        
    // Wait for the client to connect; if it succeeds, 
    // the function returns a nonzero value. If the function
    // returns zero, GetLastError returns ERROR_PIPE_CONNECTED. 
    fConnected = ConnectNamedPipe(hRemoteOutputPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

    if (fConnected && !shutdownRemotePipeThreads) {
        DebugFprintf(outlogfile, PRINT_INFO2, "[+] Remote output pipe connected. Creating a processing thread.\n");

        // Create a thread for this client. 
        hThread = CreateThread(NULL, 0, RemoteOutputHandler, (LPVOID)hRemoteOutputPipe, 0, &dwThreadId);
        if (hThread == NULL) {
            DebugFprintf(outlogfile, PRINT_ERROR, "[-] CreateThread failed, GLE=%d.\n", GetLastError());
            return -1;
        }
        else
            CloseHandle(hThread);
    }
    else {
        // The client could not connect, so close the pipe. 
        DisconnectNamedPipe(hRemoteOutputPipe);
        CloseHandle(hRemoteOutputPipe);
        hRemoteOutputPipe = INVALID_HANDLE_VALUE;
    }

    return 0;
}

int create_remote_input_pipe(std::string hostname)
{
    BOOL   fConnected = FALSE;
    DWORD  dwThreadId = 0;
    HANDLE hThread = NULL;
    SECURITY_ATTRIBUTES sa = { 0 };

    std::string stdin_pipe_name = "\\\\.\\pipe\\";
    stdin_pipe_name.append(hostname);
    stdin_pipe_name.append("I");

    // The main loop creates an instance of the named pipe and 
    // then waits for a client to connect to it. When the client 
    // connects, a thread is created to handle communications 
    // with that client, and this loop is free to wait for the
    // next client connect request. It is an infinite loop.
    DebugFprintf(outlogfile, PRINT_INFO2, "[+] Creating stdin named pipe %s\n", stdin_pipe_name.c_str());
    InitSecurityAttributes(&sa);

    hRemoteInputPipe = CreateNamedPipeA(stdin_pipe_name.c_str(), // pipe name 
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE,
        PIPE_UNLIMITED_INSTANCES, // max. instances  
        PIPE_BUFFER_SIZE,                  // output buffer size 
        PIPE_BUFFER_SIZE,                  // input buffer size 
        0,                        // client time-out 
        &sa);                    // default security attribute

    if (hRemoteInputPipe == INVALID_HANDLE_VALUE) {
        DebugFprintf(outlogfile, PRINT_ERROR, "[-] CreateNamedPipe failed, GLE=%d.\n", GetLastError());
        return -1;
    }

    // Wait for the client to connect; if it succeeds, 
    // the function returns a nonzero value. If the function
    // returns zero, GetLastError returns ERROR_PIPE_CONNECTED. 
    fConnected = ConnectNamedPipe(hRemoteInputPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
    if (fConnected && !shutdownRemotePipeThreads) {
        DebugFprintf(outlogfile, PRINT_INFO2, "[+] Remote Input Pipe connected. Creating a processing thread.\n");

        // Create a thread for this client. 
        hThread = CreateThread(NULL, 0, RemoteInputHandler, (LPVOID)hRemoteInputPipe, 0, &dwThreadId);
        if (hThread == NULL) {
            DebugFprintf(outlogfile, PRINT_ERROR, "[-] CreateThread failed, GLE=%d.\n", GetLastError());
            return -1;
        }
        else
            CloseHandle(hThread);
    }
    else {
        // The client could not connect, so close the pipe. 
        DisconnectNamedPipe(hRemoteInputPipe);
        CloseHandle(hRemoteInputPipe);
        hRemoteInputPipe = INVALID_HANDLE_VALUE;
    }

    return 0;
}

BOOL HandlePipeData(PipeData *pipe_data) {

    std::vector<unsigned char> pipe_data_vect = pipe_data->GetData();
    std::string tmp_str;
    PVOID pBuffer;

    switch (pipe_data->GetType()) {
        case CMD_TYPE:
            tmp_str = std::string(pipe_data_vect.begin(), pipe_data_vect.end());
            DebugFprintf(outlogfile, PRINT_INFO1, "[+] Starting process with cmd line: %s.\n", tmp_str.c_str());
            exec_thread = new std::thread(CreateProcessWithPipeComm, tmp_str);
            break;
        case STD_IN_TYPE:
            tmp_str = std::string(pipe_data_vect.begin(), pipe_data_vect.end());
            write_to_input(tmp_str);
            break;
        case SHELL_CODE_TYPE:
            DebugFprintf(outlogfile, PRINT_INFO1, "[+] Executing %d bytes of shellcode in new thread.\n", pipe_data_vect.size());
            pBuffer = VirtualAlloc(NULL, pipe_data_vect.size(), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
            memcpy(pBuffer, pipe_data_vect.data(), pipe_data_vect.size());
            exec_thread = new std::thread(ExecuteSC, pBuffer);
            break;
        default:
            DebugFprintf(outlogfile, PRINT_ERROR, "[+] Unknown pipe data msg type: %d.\n", pipe_data->GetType());
    }
    return TRUE;
}

DWORD WINAPI RemoteInputHandler(LPVOID lpvParam)
{
    if (lpvParam == NULL)
        return 0;

    BOOL ret = FALSE;
    HANDLE hPipe = NULL;

    // The thread's parameter is a handle to a pipe object instance. 
    hPipe = (HANDLE)lpvParam;
    char *readBuf = NULL;
    PipeData* pipe_data = new PipeData();

    DWORD bytesRead = 0, bytesAvail = 0, bytesLeft = 0, dwRead = 0;
    while (!shutdownRemotePipeThreads) {
        //Reset read counter
        dwRead = 0;
        //See how many bytes are available
        ret = PeekNamedPipe(hPipe, NULL, 0, &bytesRead, &bytesAvail, &bytesLeft);
        if (ret == TRUE) {

            if (bytesAvail >= 0) {

                //Alloc memory
                readBuf = (char *)calloc(1, bytesAvail);

                //Read the pipe data header
                ret = ReadFile(hPipe, readBuf, bytesAvail, &dwRead, NULL);
                if (!ret)
                    break;

                if (dwRead > 0) {

                    //Fill in the PipeData object until it's populated and then handle it
                    if (pipe_data->Populate(readBuf, dwRead)) {

                        //DebugFprintf(outlogfile, PRINT_ERROR, "[+] Handling the pipe data message.\n");
                        HandlePipeData(pipe_data);

                        //Delete old object and create new one
                        delete(pipe_data);
                        pipe_data = new PipeData();
                    }
                }

                //Free memory
                free(readBuf);
                readBuf = NULL;               
                   
            }            
        }
        Sleep(50);
    }
    DebugFprintf(outlogfile, PRINT_ERROR, "[*] Exiting RemoteInputHandler\n");
    return 0;
}

DWORD WINAPI RemoteOutputHandler(LPVOID lpvParam)
{
    if (lpvParam == NULL)
        return 0;

    BOOL ret = FALSE;
    HANDLE hPipe = NULL;
    DWORD bytesRead = 0, bytesAvail = 0, bytesLeft = 0;

    // The thread's parameter is a handle to a pipe object instance. 
    hPipe = (HANDLE)lpvParam;

    BOOL sleep;
    DWORD bytesWritten = 0;
    std::vector<unsigned char> tmp_byte_vector;
    while ( 1 ) {

        sleep = FALSE;
        bytesWritten = 0;
        outputBufferMtx.lock();
        if (outputBuffer.size() > 0) {

            // check to make sure pipe is empty
            ret = PeekNamedPipe(hPipe, NULL, 0, &bytesRead, &bytesAvail, &bytesLeft);
            if (ret == TRUE && bytesAvail == 0) {

                //Copy to temp buffer and clear
                tmp_byte_vector = std::vector<unsigned char>(outputBuffer.begin(), outputBuffer.end());
                outputBuffer.clear();
                //Send the output chunked as max size is 64k
                ret = chunk_pipe_write(hPipe, &tmp_byte_vector);

                //DebugFprintf(outlogfile, PRINT_INFO3, "[*] Bytes Written: %d\n", bytesWritten);
            }
            else {
                sleep = TRUE;
            }
        }
        else {

            //Break out of loop if flags are set
            if (shutdownRemotePipeThreads)
                break;
            sleep = TRUE;
        }    

        outputBufferMtx.unlock();

        //Sleep if needed
        if (sleep)
            Sleep(50);
    }

    DebugFprintf(outlogfile, PRINT_INFO3, "[*] Exiting RemoteOutputHandler\n");

    return 0;
}
