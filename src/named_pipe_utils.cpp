#include <Windows.h> 
#include <stdio.h>
#include <thread>
#include <string>
#include <vector>
#include <iostream>
#include <conio.h>
#include <mutex>
#include <aclapi.h>

#include "named_pipe_utils.h"
#include "pipe_data.h"
#include "debug.h"

bool shutdownThreads = false;
std::thread* pipe_thread_stdout = nullptr;
std::thread* pipe_thread_stdin = nullptr;
std::vector<unsigned char> tmp_data;

/* Create a DACL that will allow everyone to have full control over our pipe. */
VOID BuildDACL(PSECURITY_DESCRIPTOR pDescriptor)
{
    PSID pSid;
    EXPLICIT_ACCESS ea;
    PACL pAcl;

    SID_IDENTIFIER_AUTHORITY sia = SECURITY_WORLD_SID_AUTHORITY;

    AllocateAndInitializeSid(&sia, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0,
        &pSid);

    ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
    ea.grfAccessPermissions = FILE_ALL_ACCESS;
    ea.grfAccessMode = SET_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName = (LPTSTR)pSid;

    if (SetEntriesInAcl(1, &ea, NULL, &pAcl) == ERROR_SUCCESS)
    {
        if (SetSecurityDescriptorDacl(pDescriptor, TRUE, pAcl, FALSE) == 0)
            DebugFprintf(outlogfile, PRINT_ERROR, "[*] Failed to set DACL (%u)\n", GetLastError());
    }
    else
        DebugFprintf(outlogfile, PRINT_ERROR, "[*] Failed to add ACE in DACL (%u)\n", GetLastError());
}


/* Create a SACL that will allow low integrity processes connect to our pipe. */
VOID BuildSACL(PSECURITY_DESCRIPTOR pDescriptor)
{
    PSID pSid;
    PACL pAcl;

    SID_IDENTIFIER_AUTHORITY sia = SECURITY_MANDATORY_LABEL_AUTHORITY;
    DWORD dwACLSize = sizeof(ACL) + sizeof(SYSTEM_MANDATORY_LABEL_ACE) +
        GetSidLengthRequired(1);

    pAcl = (PACL)LocalAlloc(LPTR, dwACLSize);
    InitializeAcl(pAcl, dwACLSize, ACL_REVISION);

    AllocateAndInitializeSid(&sia, 1, SECURITY_MANDATORY_LOW_RID, 0, 0, 0, 0,
        0, 0, 0, &pSid);

    if (AddMandatoryAce(pAcl, ACL_REVISION, 0, SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
        pSid) == TRUE)
    {
        if (SetSecurityDescriptorSacl(pDescriptor, TRUE, pAcl, FALSE) == 0)
            DebugFprintf(outlogfile, PRINT_ERROR, "([*] Failed to set SACL (%u)\n", GetLastError());
    }
    else
        DebugFprintf(outlogfile, PRINT_ERROR, "[*] Failed to add ACE in SACL (%u)\n", GetLastError());
}


/* Initialize security attributes to be used by `CreateNamedPipe()' below. */
VOID InitSecurityAttributes(PSECURITY_ATTRIBUTES pAttributes)
{
    PSECURITY_DESCRIPTOR pDescriptor;

    pDescriptor = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR,
        SECURITY_DESCRIPTOR_MIN_LENGTH);
    InitializeSecurityDescriptor(pDescriptor, SECURITY_DESCRIPTOR_REVISION);

    BuildDACL(pDescriptor);
    BuildSACL(pDescriptor);

    pAttributes->nLength = sizeof(SECURITY_ATTRIBUTES);
    pAttributes->lpSecurityDescriptor = pDescriptor;
    pAttributes->bInheritHandle = TRUE;
}

BOOL chunk_pipe_write(HANDLE hPipe, std::vector<unsigned char>* pipe_data) {

    DWORD bytesWritten = 0, ret = 0;

    if (hPipe == NULL)
        return false;

    for (uint32_t i = 0; i < pipe_data->size(); i += 32768) {

        //Send the command line data for the process to execute
        if (pipe_data->size() > i + 32768) {
            tmp_data = std::vector<unsigned char>(pipe_data->begin() + i, pipe_data->begin() + i + 32768);
        }
        else {
            tmp_data = std::vector<unsigned char>(pipe_data->begin() + i, pipe_data->end());
        }

        ret = WriteFile(hPipe, reinterpret_cast<const BYTE*>(tmp_data.data()), static_cast<ULONG>(tmp_data.size()), &bytesWritten, NULL);
        if (ret == 0) {
            //DebugFprintf(outlogfile, PRINT_INFO1, "\t[*] WriteFile failed. %d\n", GetLastError());
            return false;
        }
    }

    return true;
}

void stdinpipe(std::string ip, std::string path, std::string cmd_line, std::vector<unsigned char>* sc_bytes)
{
    if (ip.size() == 0)
        ip = ".";

    HANDLE hPipe = NULL;
    DWORD bytesWritten = 0;
    std::string pipename = "\\\\" + ip + "\\" + path;

    // Try to open a named pipe; wait for it, if necessary. 
    while (!shutdownThreads) {
        hPipe = CreateFileA(pipename.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

        // Break if the pipe handle is valid.
        if (hPipe != INVALID_HANDLE_VALUE)
            break;

        // Exit if an error other than ERROR_PIPE_BUSY occurs.
        if (GetLastError() != ERROR_PIPE_BUSY) {
            DebugFprintf(outlogfile, PRINT_ERROR, "\t[-] Could not open pipe. GLE=%d\n", GetLastError());
            return;
        }

        // All pipe instances are busy, so wait for 20 seconds. 
        if (!WaitNamedPipe(pipename.c_str(), 20000)) {
            DebugFprintf(outlogfile, PRINT_ERROR, "\t[-] Could not open pipe: 20 second wait timed out.");
            return;
        }
    }

    // The pipe connected; change to message-read mode. 
    DWORD dwMode = PIPE_READMODE_MESSAGE;
    BOOL ret = SetNamedPipeHandleState(hPipe, &dwMode, NULL, NULL);
    if (!ret) {
        DebugFprintf(outlogfile, PRINT_ERROR, "\t[-] SetNamedPipeHandleState failed. GLE=%d\n", GetLastError());
        return;
    }

    //If a cmd is being executed
    if (sc_bytes->size() > 0) {

        //Create shellcode pipe data object
        ScData scDataInst = ScData(sc_bytes);
        std::vector<unsigned char>* scBytes = scDataInst.ToBytes();

        PipeData pipe_data_inst;
        pipe_data_inst.Populate((char *)scBytes->data(), (uint32_t)scBytes->size());

        //Send the shellcode data for the process to execute
        ret = chunk_pipe_write(hPipe, scBytes);

        //Free memory
        if (scBytes != nullptr)
            delete(scBytes);

        if (ret == 0) {
            DebugFprintf(outlogfile, PRINT_INFO1, "\t[*] WriteFile failed. %d\n", GetLastError());
        }

    } else if (!cmd_line.empty()) {
        //Create cmd pipe data object
        CmdData cmdDataInst = CmdData(cmd_line);
        std::vector<unsigned char>* cmdBytes = cmdDataInst.ToBytes();

        //Send the command line data for the process to execute
        ret = chunk_pipe_write(hPipe, cmdBytes);
      
        //Free memory
        if (cmdBytes != nullptr)
            delete(cmdBytes);

        if (ret == 0) {
            DebugFprintf(outlogfile, PRINT_INFO1, "\t[*] WriteFile failed. %d\n", GetLastError());
        }
    }

    DebugFprintf(outlogfile, PRINT_INFO1, "\t[*] Connecting to remote named pipe.\n");
    DebugFprintf(outlogfile, PRINT_INFO1, "\t[*] Type \"quit\" to terminate the connection or hit the \"Enter\" key on process exit.\n\n");
    std::string line = "";
    while (!shutdownThreads) {
        
        bytesWritten = 0;
        line = "";

        //Get the next command
        std::getline(std::cin, line);

        if (line.size() > 0 && line.compare("quit") == 0) {
            DebugFprintf(outlogfile, PRINT_INFO3, "\t[-] Exitting NPShellClient...\n");
            break;
        }

        //Add line delimiter
        line = line + "\n";

        //Create std in pipe data object
        StdInData stdInDataInst = StdInData(line);
        std::vector<unsigned char>* stdInBytes = stdInDataInst.ToBytes();

        ret = chunk_pipe_write(hPipe, stdInBytes);
        //ret = WriteFile(hPipe, reinterpret_cast<const BYTE*>(stdInBytes->data()), static_cast<ULONG>(stdInBytes->size()), &bytesWritten, NULL);
        
        //Free memory
        if (stdInBytes != nullptr)
            delete(stdInBytes);

        if (ret == 0) {
            DWORD err_code = GetLastError();
            //DebugFprintf(outlogfile, PRINT_INFO1, "\t[-] Namedpipe write failed: exiting %d\n", err_code);
            if (err_code == 233) {
                shutdownThreads = true;
                break;
            }
        }

    }

    CloseHandle(hPipe);
}

void stdoutpipe(std::string ip, std::string path)
{
    HANDLE hPipe = NULL;
    std::string pipename = "\\\\" + ip + "\\" + path;

    // Try to open a named pipe; wait for it, if necessary. 
    while (!shutdownThreads) {
        hPipe = CreateFileA(pipename.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

        // Break if the pipe handle is valid.
        if (hPipe != INVALID_HANDLE_VALUE)
            break;

        // Exit if an error other than ERROR_PIPE_BUSY occurs.
        if (GetLastError() != ERROR_PIPE_BUSY) {
            DebugFprintf(outlogfile, PRINT_ERROR, "\t[-] Could not open pipe. GLE=%d\n", GetLastError());
            return;
        }

        // All pipe instances are busy, so wait for 20 seconds. 
        if (!WaitNamedPipeA(pipename.c_str(), 20000)) {
            DebugFprintf(outlogfile, PRINT_ERROR, "\t[-] Could not open pipe: 20 second wait timed out.");
            return;
        }
    }

    // The pipe connected; change to message-read mode. 
    DWORD dwMode = PIPE_READMODE_MESSAGE;
    BOOL ret = SetNamedPipeHandleState(hPipe, &dwMode, NULL, NULL);
    if (!ret) {
        DebugFprintf(outlogfile, PRINT_ERROR, "\t[-] SetNamedPipeHandleState failed. GLE=%d\n", GetLastError());
        return;
    }

    DWORD dwRead = 0;
    char* buffer;
    DWORD bytesRead = 0, bytesAvail = 0, bytesLeft = 0;

    while (!shutdownThreads) {
        ret = PeekNamedPipe(hPipe, NULL, 0, &bytesRead, &bytesAvail, &bytesLeft);
        if (ret == TRUE && bytesAvail > 0) {

            buffer = (char*)calloc(1, bytesAvail + 1);
            ret = ReadFile(hPipe, buffer, bytesAvail, &dwRead, NULL);
            if (ret == TRUE) {

                if (dwRead > 0) {
                    //printf("\nBytes read: %d\n", dwRead);
                    printf("%s", buffer);
                    fflush(stdout);
                }
            }
            else {
                shutdownThreads = true;
                DebugFprintf(outlogfile, PRINT_INFO1, "\t[-] Namedpipe read failed: exiting %d\n", GetLastError());
                break;
            }

            //Free it
            if (buffer != NULL)
                free(buffer);

        } else {
            Sleep(50);
        }
    }

    CloseHandle(hPipe);
}

void start_client_threads(std::string ip, std::string hostname, std::string cmd_line, std::vector<unsigned char>* sc_bytes)
{
    shutdownThreads = false;
    std::string stdin_pipe_name = "pipe\\";
    stdin_pipe_name.append(hostname);
    stdin_pipe_name.append("I");

    std::string stdout_pipe_name = "pipe\\";
    stdout_pipe_name.append(hostname);
    stdout_pipe_name.append("O");

    pipe_thread_stdout = new std::thread(stdoutpipe, ip, stdout_pipe_name);
    pipe_thread_stdin = new std::thread(stdinpipe, ip, stdin_pipe_name, cmd_line, sc_bytes);
}

void wait_for_stdin_thread()
{
    if (pipe_thread_stdin != nullptr) {
        pipe_thread_stdin->join();
        delete pipe_thread_stdin;
        pipe_thread_stdin = nullptr;
    }
}

void stop_client_threads()
{
    shutdownThreads = true;

    if (pipe_thread_stdout != nullptr) {
        pipe_thread_stdout->join();
        delete pipe_thread_stdout;
        pipe_thread_stdout = nullptr;
    }

    if (pipe_thread_stdin != nullptr) {
        pipe_thread_stdin->join();
        delete pipe_thread_stdin;
        pipe_thread_stdin = nullptr;
    }
}

void connect_named_pipes(std::string ip, std::string hostname, std::string cmd, std::vector<unsigned char>* sc_bytes)
{
    start_client_threads(ip, hostname, cmd, sc_bytes);

    wait_for_stdin_thread();

    stop_client_threads();
}
