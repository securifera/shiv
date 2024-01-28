#include <windows.h> 
#include <winsvc.h>
#include <string>

#include "debug.h"
#include "svc_info.h"
#include "process_info.h"


#pragma comment(lib, "Advapi32.lib")

BOOL get_svc_config(SC_HANDLE sc_manager_handle, std::string svc_name, ProcessInfo *proc_info )
{
	SC_HANDLE schService;
	LPQUERY_SERVICE_CONFIG lpsc = NULL;
	DWORD dwBytesNeeded = 0, cbBufSize = 0, dwError = 0;

	// Get a handle to the service 
	schService = OpenService( sc_manager_handle, svc_name.c_str(), SERVICE_QUERY_CONFIG); 
	if (schService == NULL)
	{
		DbgFprintf(outlogfile, PRINT_ERROR, "OpenService failed. Error: %d.\n", GetLastError());
		return FALSE;
	}

	// Get the configuration information.
	if (!QueryServiceConfig( schService, NULL, 0, &dwBytesNeeded))
	{
		dwError = GetLastError();
		if (ERROR_INSUFFICIENT_BUFFER == dwError)
		{
			cbBufSize = dwBytesNeeded;
			lpsc = (LPQUERY_SERVICE_CONFIG)malloc(cbBufSize);
			if (lpsc == NULL) {
				DbgFprintf(outlogfile, PRINT_ERROR, "[-] calloc returned NULL\n");
				exit(1);
			}

		}
		else
		{
			DbgFprintf(outlogfile, PRINT_ERROR, "QueryServiceConfig failed. Error: %d.\n", dwError);
			goto cleanup;
		}
	}

	if (!QueryServiceConfig( schService, lpsc, cbBufSize, &dwBytesNeeded))
	{
		DbgFprintf(outlogfile, PRINT_ERROR, "QueryServiceConfig failed. Error: %d.\n", GetLastError());
		goto cleanup;
	}

	//Set binary path
	proc_info->SetExePath(lpsc->lpBinaryPathName);
	proc_info->SetUsername(lpsc->lpServiceStartName);
	proc_info->SetServiceName(svc_name);

cleanup:
	CloseServiceHandle(schService);
	if (lpsc)
		free(lpsc);

	return TRUE;
}

BOOL get_service_info(std::unordered_map<size_t, ProcessInfo *> *pid_process_info_map) {

	SC_HANDLE sc_mgr_handle = NULL;
	char * pBuf = NULL;
	DWORD  dwBufSize = 0;
	DWORD  dwBufSizeNeeded = 0;
	DWORD  dwNumberOfServices = 0;
	LPENUM_SERVICE_STATUS_PROCESS pInfo = NULL;
	DWORD service_pid = 0;

	sc_mgr_handle = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_CONNECT);
	if (sc_mgr_handle == NULL)
	{
		DbgFprintf(outlogfile, PRINT_ERROR, "Unable to open sc manager. Error: %d.\n", GetLastError());
		return FALSE;
	}

	//Query services once to get correct buffer size, always fails
	if (EnumServicesStatusEx(sc_mgr_handle, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
		SERVICE_ACTIVE, NULL, dwBufSize, &dwBufSizeNeeded, &dwNumberOfServices, NULL, NULL) == 0)
	{

		DWORD err = GetLastError();
		if (ERROR_MORE_DATA == err)
		{
			dwBufSize = dwBufSizeNeeded;
			pBuf = (char *)malloc(dwBufSize);

			//Query services again with correct buffer size
			if (EnumServicesStatusEx(sc_mgr_handle, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
				SERVICE_ACTIVE, (LPBYTE)pBuf, dwBufSize, &dwBufSizeNeeded, &dwNumberOfServices, NULL, NULL) == 0)
			{
				DbgFprintf(outlogfile, PRINT_ERROR, "Could not enumerate services. Error: %d.\n", GetLastError()); 
				free(pBuf);
				return FALSE;
			}

			ENUM_SERVICE_STATUS_PROCESS* lpServiceStatus = (ENUM_SERVICE_STATUS_PROCESS*)pBuf;
			for (int i = 0; i < (int)dwNumberOfServices; i++)
			{
				std::string svc_name(lpServiceStatus[i].lpServiceName);
				service_pid = lpServiceStatus[i].ServiceStatusProcess.dwProcessId;

				std::unordered_map<size_t, ProcessInfo *>::iterator map_it;
				map_it = pid_process_info_map->find(service_pid);
				if (map_it != pid_process_info_map->end()) {

					//Get process info object
					std::pair<size_t, ProcessInfo *> log_path_pair = *map_it;
					ProcessInfo *proc_info = (ProcessInfo *)log_path_pair.second;

					get_svc_config(sc_mgr_handle, svc_name, proc_info);
				}
	
			}
		}
		else
		{
			DbgFprintf(outlogfile, PRINT_ERROR, "Could not enumerate services. Error: %d.\n", GetLastError());
			return FALSE;
		}
	}

	//Close service handle
	if (sc_mgr_handle)
		CloseServiceHandle(sc_mgr_handle);


	return TRUE;
}