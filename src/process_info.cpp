#include <windows.h> 
#include <stdio.h>
#include <winternl.h>
#include <vector>
#include <psapi.h>
#include <sstream>
#include <iomanip>

#include "debug.h"
#include "process_info.h"
#include "svc_info.h"

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ntdll.lib")

BOOL get_session_id(ProcessInfo *psInfo)
{
	DWORD dwSessionId = 0;
	BOOL ret_val = TRUE;	
		
	//Attempt to get session id
	ProcessIdToSessionId((DWORD)psInfo->GetPid(), &dwSessionId);

	//Set the session id
	psInfo->SetSessionId(dwSessionId);

	return ret_val;
}

DWORD get_arch_sysinfo()
{
	DWORD dwNativeArch = PROCESS_ARCH_UNKNOWN;
	SYSTEM_INFO SystemInfo = { 0 };

	dwNativeArch = PROCESS_ARCH_X86;

	GetNativeSystemInfo(&SystemInfo);
	switch (SystemInfo.wProcessorArchitecture)
	{
		case PROCESSOR_ARCHITECTURE_AMD64:
			dwNativeArch = PROCESS_ARCH_X64;
			break;
		case PROCESSOR_ARCHITECTURE_IA64:
			dwNativeArch = PROCESS_ARCH_IA64;
			break;
		case PROCESSOR_ARCHITECTURE_INTEL:
			dwNativeArch = PROCESS_ARCH_X86;
			break;
		default:
			dwNativeArch = PROCESS_ARCH_UNKNOWN;
			break;
	}
	
	return dwNativeArch;
}

DWORD get_arch(ProcessInfo *psInfo)
{
	DWORD result = PROCESS_ARCH_UNKNOWN;
	static DWORD dwNativeArch = PROCESS_ARCH_UNKNOWN;
	HANDLE hProcess = NULL;
	BOOL bIsWow64 = FALSE;

	if (dwNativeArch == PROCESS_ARCH_UNKNOWN)
		dwNativeArch = get_arch_sysinfo();
		
	result = PROCESS_ARCH_UNKNOWN;

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (DWORD)psInfo->GetPid());
	if (!hProcess)
	{
		hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)psInfo->GetPid());
		if (!hProcess)
		{
			DbgFprintf(outlogfile, PRINT_INFO3, "Unable to open process (get_arch). Error: %d.\n", GetLastError());
			return FALSE;
		}
	}

	if (!IsWow64Process(hProcess, &bIsWow64))
	{
		DbgFprintf(outlogfile, PRINT_ERROR, "Unable to check arch type. Error: %d.\n", GetLastError());
		return FALSE;
	}

	if (bIsWow64)
		result = PROCESS_ARCH_X86;
	else
		result = dwNativeArch;

	if (hProcess)
		CloseHandle(hProcess);

	//Set architecture
	psInfo->SetArch((unsigned short)result);

	return TRUE;
}

BOOL get_exe_path(ProcessInfo *psInfo)
{
	BOOL success = TRUE;
	HANDLE hProcess = NULL;
	
	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, (DWORD)psInfo->GetPid());
	if (!hProcess) {
		DbgFprintf(outlogfile, PRINT_INFO3, "Unable to open process (get_exe_path). Error: %d.\n", GetLastError());
		return success;
	}

	char mod_path[MAX_PATH];
	memset(mod_path, 0, MAX_PATH);

	if (!GetModuleFileNameEx(hProcess, NULL, mod_path, MAX_PATH)) {

		DWORD dwSize = MAX_PATH;
		if (!QueryFullProcessImageName(hProcess, 0, mod_path, &dwSize)){

			if (!GetProcessImageFileName(hProcess, (LPSTR)mod_path, MAX_PATH)){

				DWORD dwSize = 0;
				PROCESS_BASIC_INFORMATION BasicInformation = { 0 };
				RTL_USER_PROCESS_PARAMETERS params = { 0 };
				_PEB peb = { 0 };
					
				success = FALSE;
				if (NtQueryInformationProcess(hProcess, ProcessBasicInformation, &BasicInformation, sizeof(PROCESS_BASIC_INFORMATION), &dwSize) == ERROR_SUCCESS) {
					
					if (BasicInformation.PebBaseAddress) {

						if (ReadProcessMemory(hProcess, BasicInformation.PebBaseAddress, &peb, 64, NULL)) { // (just read in the first 64 bytes of PEB)

							if (peb.ProcessParameters) {

								if (ReadProcessMemory(hProcess, peb.ProcessParameters, &params, sizeof(params), NULL)) {

									if (ReadProcessMemory(hProcess, params.ImagePathName.Buffer, mod_path, params.ImagePathName.Length, NULL))
										success = TRUE;	
									
								}
							}
						}
					}
				}					
			}					
		}

	}
		
	//Close handle
	if (hProcess)
		CloseHandle(hProcess);

	//Set the process exe path
	if (success)
		psInfo->SetExePath(mod_path);

	return success;
}

BOOL get_process_owner(ProcessInfo *psInfo)
{
	BOOL success = FALSE;
	HANDLE hProcess = NULL;
	HANDLE hToken = NULL;
	TOKEN_USER * pUser = NULL;
	SID_NAME_USE peUse;
	DWORD user_len = 0;
	DWORD domain_len = 0;
	DWORD dwLength = 0;
	char user[512] = { 0 };
	char domain[512] = { 0 };
	char user_domain[1024] = { 0 };


	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (DWORD)psInfo->GetPid());
	if (hProcess) {


		if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {

			GetTokenInformation(hToken, TokenUser, NULL, 0, &dwLength);

			pUser = (TOKEN_USER *)malloc(dwLength);
			if (pUser) {

				if (GetTokenInformation(hToken, TokenUser, pUser, dwLength, &dwLength)) {
	
					user_len = sizeof(user);
					domain_len = sizeof(domain);

					if (LookupAccountSid(NULL, pUser->User.Sid, user, &user_len, domain, &domain_len, &peUse)) {
						_snprintf_s(user_domain, 1024 - 1, "%s\\%s", domain, user);
						psInfo->SetUsername(user_domain);
						success = TRUE;
					}
					else {
						DbgFprintf(outlogfile, PRINT_ERROR, "Unable to lookup accound sid. Error: %d.\n", GetLastError());
						success = FALSE;
					}
				}
				else {
					DbgFprintf(outlogfile, PRINT_ERROR, "Unable to get token information. Error: %d.\n", GetLastError());
					success = FALSE;
				}
			}
			else {
				DbgFprintf(outlogfile, PRINT_ERROR, "Unable to allocate memory. Error: %d.\n", GetLastError());
				success = FALSE;
			}
		}
		else {
			DbgFprintf(outlogfile, PRINT_ERROR, "Unable to open process token. Error: %d.\n", GetLastError());
			success = FALSE;
		}
	}
	else {
		DbgFprintf(outlogfile, PRINT_INFO3, "Unable to open process (get_process_owner). Error: %d.\n", GetLastError());
		success = FALSE;
	}


	if (pUser)
		free(pUser);

	if (hToken)
		CloseHandle(hToken);

	if (hProcess)
		CloseHandle(hProcess);

	return success;
}

BOOL get_processes(std::unordered_map<size_t, ProcessInfo *> *pid_process_info_map)
{
	DWORD result = ERROR_INVALID_HANDLE;
	HANDLE hProcessSnap = NULL;
	PROCESSENTRY32 pe32 = { 0 };

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		DbgFprintf(outlogfile, PRINT_ERROR, "Unable to get handle to CreateToolhelp32Snapshot.\n");
		return FALSE;
	}

	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hProcessSnap, &pe32)) {
		DbgFprintf(outlogfile, PRINT_ERROR, "Process32FirstW failed. Error: %d.\n", GetLastError());
		return FALSE;
	}

	result = ERROR_SUCCESS;
	do	{

		ProcessInfo *psInfo = new ProcessInfo(pe32.th32ProcessID);

		//Set parent PID
		psInfo->SetParentPid(pe32.th32ParentProcessID);

		//Set the exe name
		psInfo->SetExeName(pe32.szExeFile);

		//Get the full path of the process executable
		get_exe_path(psInfo);

		//Get user that spawned the process
		get_process_owner(psInfo);

		//Get the session id
		get_session_id(psInfo);

		//Get the architecture
		get_arch(psInfo);

		//Add process object to list
		std::pair<size_t, ProcessInfo *> pid_pair(psInfo->GetPid(), psInfo);
		pid_process_info_map->insert(pid_pair);
				

	} while (Process32Next(hProcessSnap, &pe32));

	if (hProcessSnap)
		CloseHandle(hProcessSnap);

	//Fill in any service information
	get_service_info(pid_process_info_map);
	
	return result;
}

std::string ProcessInfo::GetArch() 
{ 
	std::string arch_str;
	switch (this->process_arch) {
		case PROCESS_ARCH_X64:
			arch_str.assign("x64");
			break;
		case PROCESS_ARCH_IA64:
			arch_str.assign("ia64");
			break;
		case PROCESS_ARCH_X86:
			arch_str.assign("x86");
			break;
		default:
			arch_str.assign("Unknown");
	}

	return arch_str;
};

void print_process_data(std::unordered_map<size_t, ProcessInfo *> process_info_map) {

	//Get groups for each user
	if (process_info_map.size() > 0) {

		DebugFprintf(outlogfile, PRINT_INFO1, "PID,PPID,Session Id,Username,Arch,Binary Name,Binary Path,Service Name,Open Ports,Connections\n");
		for (std::unordered_map<size_t, ProcessInfo *>::iterator proc_info_it = process_info_map.begin();
			proc_info_it != process_info_map.end(); ++proc_info_it) {

			//Get proc info
			ProcessInfo *proc_info_data = proc_info_it->second;

			//Print pid
			DebugFprintf(outlogfile, PRINT_INFO1, "%d,", proc_info_data->GetPid());

			//Print parent pid
			DebugFprintf(outlogfile, PRINT_INFO1, "%d,", proc_info_data->GetParentPid());

			//Print session id
			DebugFprintf(outlogfile, PRINT_INFO1, "%d,", proc_info_data->GetSessionId());

			//Print username
			DebugFprintf(outlogfile, PRINT_INFO1, "%s,", proc_info_data->GetUsername().c_str());

			//Print arch
			DebugFprintf(outlogfile, PRINT_INFO1, "%s,", proc_info_data->GetArch().c_str());

			//Print exe name
			DebugFprintf(outlogfile, PRINT_INFO1, "%s,", proc_info_data->GetExeName().c_str());

			//Print exe path
			DebugFprintf(outlogfile, PRINT_INFO1, "\"%s\",", proc_info_data->GetExePath().c_str());

			//Print service name
			DebugFprintf(outlogfile, PRINT_INFO1, "%s,", proc_info_data->GetServiceName().c_str());

			//Print ports
			DebugFprintf(outlogfile, PRINT_INFO1, "\"");
			std::vector<std::string> port_list = proc_info_data->GetOpenPorts();
			for (std::vector<std::string>::iterator it = port_list.begin(); it != port_list.end(); ++it) {
				std::string port_str = *it;
				DebugFprintf(outlogfile, PRINT_INFO1, "%s,", port_str.c_str());
			}
			DebugFprintf(outlogfile, PRINT_INFO1, "\",");

			//Print connections
			DebugFprintf(outlogfile, PRINT_INFO1, "\"");
			std::vector<std::string> connections = proc_info_data->GetConnections();
			for (std::vector<std::string>::iterator it = connections.begin(); it != connections.end(); ++it) {
				std::string conn_str = *it;
				DebugFprintf(outlogfile, PRINT_INFO1, "%s,", conn_str.c_str());
			}
			DebugFprintf(outlogfile, PRINT_INFO1, "\",");

			DebugFprintf(outlogfile, PRINT_INFO1, "\n");
		}
		DebugFprintf(outlogfile, PRINT_INFO1, "\n");
	}

	return;

}