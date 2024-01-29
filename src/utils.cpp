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

#include <vector>
#include <winsock2.h>
#include <string>
#include <windows.h> 
#include <iphlpapi.h>
#include <time.h>
#include <stdio.h>
#include <iostream>
#include <lm.h>
#include <locale>
#include <codecvt>

#include "utils.h"
#include "debug.h"
#include "user_info.h"
#include "iis.h"
#include "dnt.h"

#pragma comment(lib, "netapi32.lib")

std::wstring s2ws(const std::string& str)
{
	using convert_typeX = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_typeX, wchar_t> converterX;

	return converterX.from_bytes(str);
}

std::string ws2s(const std::wstring& wstr)
{
	using convert_typeX = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_typeX, wchar_t> converterX;

	return converterX.to_bytes(wstr);
}

BOOL remotely_change_user_pw(std::string remote_host, std::string username, std::string old_password, std::string new_password)
{
	DWORD dwError = 0;
	NET_API_STATUS nStatus;

	std::wstring wremote_host(L"\\\\");
	wremote_host.append(remote_host.begin(), remote_host.end());
	
	std::wstring wusername(username.begin(), username.end());
	std::wstring wold_password(old_password.begin(), old_password.end());
	std::wstring wnew_password(new_password.begin(), new_password.end());

	nStatus = NetUserChangePassword(wremote_host.c_str(), wusername.c_str(), wold_password.c_str(), wnew_password.c_str());
	if (nStatus == NERR_Success)
		return TRUE;
	else
		return FALSE;

}

BOOL check_write_access(std::string file_path) {

	bool is_writable = true;

	char tmp_file_name[MAX_PATH];
	memset(tmp_file_name, 0, MAX_PATH);

	GetTempFileName(file_path.c_str(), "tmp_axfr_", 0, tmp_file_name);
	if (strlen(tmp_file_name) == 0) {
		is_writable = false;
	}
	else {

		HANDLE file = CreateFile(tmp_file_name, GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (file == INVALID_HANDLE_VALUE)
		{
			is_writable = false;
		}
		else
		{
			CloseHandle(file);
			DeleteFile(tmp_file_name);
			is_writable = true;
		}
	}

	return is_writable;
}

DWORD enable_token_priv(HANDLE token, char* priv)
{
	HANDLE hToken = token;
	DWORD dwError = 0;
	TOKEN_PRIVILEGES privileges;

	if (hToken == NULL && !OpenProcessToken(GetCurrentProcess(), MAXIMUM_ALLOWED, &hToken))
	{
		dwError = GetLastError();
		goto exit;
	}

	if (!LookupPrivilegeValue(NULL, priv, &privileges.Privileges[0].Luid))
	{
		dwError = GetLastError();
		goto exit;
	}

	privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	privileges.PrivilegeCount = 1;

	if (AdjustTokenPrivileges(hToken, FALSE, &privileges, 0, NULL, NULL) == 0)
	{
		dwError = GetLastError();
		goto exit;
	}

exit:
	if (token == NULL && hToken)
		CloseHandle(hToken);

	return dwError;
}

BOOL list_files(std::string file_path, std::vector<FileInfo *>* file_list)
{
	WIN32_FIND_DATA ffd;
	LARGE_INTEGER filesize;
	HANDLE hFind = INVALID_HANDLE_VALUE;
	DWORD dwError = 0;

	// If the directory is not specified as a command-line argument, print usage
	if (file_path.length() == 0 || file_path.length() > MAX_PATH){
		DbgFprintf(outlogfile, PRINT_ERROR, "[-] File path provided is empty or greater than MAX_PATH. Aborting.");
		return FALSE;
	}

	//Add search part
	file_path.append("\\*");

	// Find the first file in the directory
	hFind = FindFirstFile(file_path.c_str(), &ffd);
	if (INVALID_HANDLE_VALUE == hFind)
	{
		DbgFprintf(outlogfile, PRINT_ERROR, "[-] Error listing files in %s.", file_path.c_str());
		return FALSE;
	}

	// List all the files in the directory with some info about them
	do
	{
		FileInfo *aff = new FileInfo(ffd.cFileName);
		if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			aff->SetType(FILEINFO_DIRECTORY);
			//DbgFprintf(outlogfile, PRINT_INFO1, "%s   <DIR>\n", ffd.cFileName);
		}
		else
		{
			aff->SetType(FILEINFO_DIRECTORY);
			filesize.LowPart = ffd.nFileSizeLow;
			filesize.HighPart = ffd.nFileSizeHigh;
			aff->SetSize(filesize);
			//DbgFprintf(outlogfile, PRINT_INFO1, "%s %ld bytes\n", ffd.cFileName, filesize.QuadPart);
		}
		file_list->push_back(aff);

	}
	while (FindNextFile(hFind, &ffd) != 0);

	dwError = GetLastError();
	if (dwError != ERROR_NO_MORE_FILES) {
		DbgFprintf(outlogfile, PRINT_ERROR, "[-] Error while listing files in %d.", dwError);
	}

	FindClose(hFind);

	return TRUE;

}

void format_err()
{
	// Retrieve the system error message for the last-error code
	LPVOID lpMsgBuf;
	DWORD dw = GetLastError();
	FormatMessage( FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, dw, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&lpMsgBuf, 0, NULL);
	LocalFree(lpMsgBuf);
}

BOOL check_pw(std::string username, std::string domain, std::string password ) {

	HANDLE hToken;
	return LogonUser(username.c_str(), domain.c_str(), password.c_str(), 
		LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &hToken );
}

BOOL get_active_users( std::vector<std::string> *user_list ){

	// Use LPUSER_INFO_1 type for more Level 1 detail info.
	LPUSER_INFO_1 pBuf = NULL;
	LPUSER_INFO_1 pTmpBuf;
	DWORD dwLevel = 1;
	DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
	DWORD dwEntriesRead = 0;
	DWORD dwTotalEntries = 0;
	DWORD dwResumeHandle = 0;
	DWORD i;
	DWORD flags = 0;

	NET_API_STATUS nStatus;
	LPTSTR pszServerName = NULL;
	BOOL ret_val = TRUE;

	wchar_t* logon_srv_var = NULL;
	if (get_domain_controller(&logon_srv_var) == FALSE)
		return FALSE;
	   
	do
	{
		nStatus = NetUserEnum(logon_srv_var, dwLevel, FILTER_NORMAL_ACCOUNT, 
			(LPBYTE*)&pBuf, dwPrefMaxLen, &dwEntriesRead, &dwTotalEntries, &dwResumeHandle);

		// If the call succeeds,
		if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA))
		{

			if ((pTmpBuf = pBuf) != NULL)
			{

				// Loop through the entries.
				for (i = 0; (i < dwEntriesRead); i++)
				{

					// Check buffer
					if (pTmpBuf == NULL){
						DbgFprintf(outlogfile, PRINT_ERROR, "An access violation has occurred.\n");
						break;
					}

					// Print the name of the user account, flag and their privilege.
					flags = pTmpBuf->usri1_flags;
					DWORD disabled = flags & UF_ACCOUNTDISABLE;
					if (((flags & UF_ACCOUNTDISABLE) > 0))
						DbgFprintf(outlogfile, PRINT_INFO3, "Account disabled.\n");
					else if ((flags & UF_LOCKOUT) > 0)
						DbgFprintf(outlogfile, PRINT_INFO3, "Account locked.\n");
					else if ((flags & UF_PASSWORD_EXPIRED) > 0)
						DbgFprintf(outlogfile, PRINT_INFO3, "Account expired.\n");
					else {
						std::wstring wuser_name(pTmpBuf->usri1_name);
						std::string user_name = ws2s(wuser_name);
						//std::string user_name(wuser_name.begin(), wuser_name.end());
						user_list->push_back(user_name);
					}

					pTmpBuf++;

				}

			}

		}
		else {
			DbgFprintf(outlogfile, PRINT_ERROR, "A system error has occurred: %d\n", nStatus);
			ret_val = FALSE;
		}

		// Release the allocated buffer.
		if (pBuf != NULL)
		{
			NetApiBufferFree(pBuf);
			pBuf = NULL;
		}

	}
	while (nStatus == ERROR_MORE_DATA);

	// Check again for allocated memory.
	if (pBuf != NULL)
		NetApiBufferFree(pBuf);
	
	return 0;

}


std::wstring get_computer_name() {

	std::wstring computer_name;
	DWORD buf_size = (MAX_PATH * sizeof(wchar_t)) + 2;
	wchar_t* buffer = (wchar_t*)calloc(1, buf_size);
	buf_size = buf_size - 2;
	if (buffer == NULL) {
		return computer_name;
	}

	if (GetComputerNameW(buffer, &buf_size) == 0)
		DbgFprintf(outlogfile, PRINT_ERROR, "Unable to get computer name. Error: %d", GetLastError());
	else
		computer_name.assign(buffer);
	
	//Free the buffer
	if (buffer) {
		free(buffer);
		buffer = NULL;
	}

	return computer_name;
}


std::wstring get_logon_server() {

	std::wstring wdomain;
	wchar_t* logon_srv_var = NULL;

	//Attempt to get the domain controller
	if (get_domain_controller(&logon_srv_var) == FALSE) {
		return wdomain;
	}

	//DWORD buf_size = (MAX_PATH * sizeof(wchar_t)) + 2;
	//wchar_t* buffer = (wchar_t*)calloc(1, buf_size);
	//buf_size = buf_size - 2;
	//if (buffer == NULL) {


	//	return wdomain;
	//}

	//if (GetComputerNameW(buffer, &buf_size) == 0) {
	//	DbgFprintf(outlogfile, PRINT_ERROR, "Unable to get computer name. Error: %d", GetLastError());

	//	//Free the buffer
	//	if (buffer) {
	//		free(buffer);
	//		buffer = NULL;
	//	}

	//	return wdomain;
	//}

	std::wstring computer_name = get_computer_name();

	//Check if the logonserver is the current computer
	if (wcsstr(logon_srv_var, computer_name.c_str()) == 0) {
		wdomain = std::wstring(logon_srv_var);
		if (logon_srv_var)
			free(logon_srv_var);	
	}

	return wdomain;
}

void print_env()
{

	LPTSTR lpszVariable;
	LPCH lpvEnv;

	// Get a pointer to the environment block.
	lpvEnv = GetEnvironmentStrings();

	// If the returned pointer is NULL, exit.
	if (lpvEnv == NULL) {
		DbgFprintf(outlogfile, PRINT_ERROR, "GetEnvironmentStrings() failed.");
		return;
	}
	DebugFprintf(outlogfile, PRINT_ERROR, "\n[*] Printing Environment Variables.\n");

	// Variable strings are separated by NULL byte, and the block is terminated by a NULL byte.
	for (lpszVariable = (LPTSTR)lpvEnv; *lpszVariable; lpszVariable++)
	{
		while (*lpszVariable)
			putchar(*lpszVariable++);
		putchar('\n');
	}

	if (FreeEnvironmentStrings(lpvEnv) == 0)
		DbgFprintf(outlogfile, PRINT_ERROR, "Failed to free EnvironmentStrings memory.");

	return;
}


BOOL get_user_groups_all(std::string username, std::string domain, std::unordered_map<std::string, UserInfo*> *user_info_map) {

	BOOL ret_val = FALSE;

	std::wstring logon_svr_w;
	if (domain.length() == 0)
		logon_svr_w = get_logon_server();
	else
		logon_svr_w = std::wstring(domain.begin(), domain.end());

	// If we are on a domain
	if (logon_svr_w.length() > 0) {

		char* domain_str = (char *)calloc(1, MAX_PATH);
		if (!domain_str)
			return ret_val;

		std::string domain_username;
		DWORD dwSize = MAX_PATH - 1;
		if (!GetComputerNameEx(ComputerNameDnsDomain, domain_str, &dwSize))
			domain_username = ws2s(logon_svr_w);
			//domain_username = std::string(logon_svr_w.begin(), logon_svr_w.end());
		else {
			//Prepend domain str
			if (domain_str) {
				domain_username = std::string(domain_str);
				free(domain_str);
			}
		}

		//Append the username
		domain_username.append("\\");
		domain_username.append(username);

		UserInfo* user_data_inst = new UserInfo(domain_username);
		std::pair<std::string, UserInfo*> user_info_pair(domain_username, user_data_inst);
		user_info_map->insert(user_info_pair);

		//Get users
		get_user_groups(username, logon_svr_w, user_data_inst);
		get_user_localgroups(username, logon_svr_w, user_data_inst);
	}

	//Get group information
	std::wstring empty_str;

	std::string local_user(".\\");
	local_user.append(username);
	UserInfo* user_data_inst = new UserInfo(local_user);
	std::pair<std::string, UserInfo*> user_info_pair(local_user, user_data_inst);
	user_info_map->insert(user_info_pair);

	//Get users
	get_user_groups(username, empty_str, user_data_inst);
	get_user_localgroups(username, empty_str, user_data_inst);

	return TRUE;

}

BOOL get_user_groups(std::string username, std::wstring wdomain, UserInfo* user_info) {
	
	LPGROUP_USERS_INFO_0 pBuf = NULL;
	DWORD dwLevel = 0;
	DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
	DWORD dwEntriesRead = 0;
	DWORD dwTotalEntries = 0;
	NET_API_STATUS nStatus;
	BOOL ret_val = TRUE;

	wchar_t* logon_svr_ptr = NULL;
	if (wdomain.length() > 0)
		logon_svr_ptr = (wchar_t*)wdomain.c_str();

	// Call the NetUserGetGroups function, specifying level 0.
	std::wstring wUsername(username.begin(), username.end());
	nStatus = NetUserGetGroups(logon_svr_ptr, wUsername.c_str(),
		dwLevel, (LPBYTE*)&pBuf, dwPrefMaxLen, &dwEntriesRead, &dwTotalEntries);

	// If the call succeeds,
	if (nStatus == NERR_Success)
	{
		LPGROUP_USERS_INFO_0 pTmpBuf;
		if ((pTmpBuf = pBuf) != NULL)
		{
			// Loop through the entries; print the name of the global groups to which the user belongs.
			for (DWORD i = 0; i < dwEntriesRead; i++)
			{

				if (pTmpBuf == NULL)
				{
					DbgFprintf(outlogfile, PRINT_ERROR, "An access violation has occurred\n");
					ret_val = FALSE;
					break;
				}

				std::wstring wgroup_name(pTmpBuf->grui0_name);
				std::string group_name = ws2s(wgroup_name);
				//std::string group_name(wgroup_name.begin(), wgroup_name.end());
				user_info->AddGroup(group_name);

				pTmpBuf++;
			}
		}

	}
	else {
		DbgFprintf(outlogfile, PRINT_ERROR, "A system error has occurred: %d\n", nStatus);
		ret_val = FALSE;
	}

	// Free the allocated buffer.
	if (pBuf != NULL) {
		NetApiBufferFree(pBuf);
		pBuf;
	}	

	return ret_val;
}


BOOL get_users_in_group_all(std::string group, std::string domain, std::unordered_map<std::string, std::vector<std::string>*>* group_user_list_map) {

	BOOL ret_val = FALSE;

	std::wstring logon_svr_w;
	if (domain.length() == 0)
		logon_svr_w = get_logon_server();
	else
		logon_svr_w = std::wstring(domain.begin(), domain.end());

	// If we are on a domain
	if (logon_svr_w.length() > 0) {

		char* domain_str = (char*)calloc(1, MAX_PATH);
		if (!domain_str)
			return ret_val;

		std::string domain_groupname;
		DWORD dwSize = MAX_PATH - 1;
		if (!GetComputerNameEx(ComputerNameDnsDomain, domain_str, &dwSize))
			domain_groupname = ws2s(logon_svr_w);
			//domain_groupname = std::string(logon_svr_w.begin(), logon_svr_w.end());
		else {
			//Prepend domain str
			if (domain_str) {
				domain_groupname = std::string(domain_str);
				free(domain_str);
			}
		}

		//Append the username
		domain_groupname.append("\\");
		domain_groupname.append(group);

		std::vector<std::string> *user_list = new std::vector<std::string>();
		std::pair<std::string, std::vector<std::string>*> group_userlist_pair(domain_groupname, user_list);
		group_user_list_map->insert(group_userlist_pair);

		//Get users
		get_users_in_group(group, logon_svr_w, user_list);
		get_users_in_localgroup(group, logon_svr_w, user_list);
	}

	//Get group information
	std::wstring empty_str;

	std::string local_group(".\\");
	local_group.append(group);

	std::vector<std::string>* user_list = new std::vector<std::string>();
	std::pair<std::string, std::vector<std::string>*> group_userlist_pair(local_group, user_list);
	group_user_list_map->insert(group_userlist_pair);

	//Get users
	get_users_in_group(group, empty_str, user_list);
	get_users_in_localgroup(group, empty_str, user_list);

	return TRUE;

}

BOOL get_users_in_group(std::string group, std::wstring wdomain, std::vector<std::string>* user_list) {

	LPGROUP_USERS_INFO_0 pBuf = NULL;
	DWORD dwLevel = 0;
	DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
	DWORD dwEntriesRead = 0;
	DWORD dwTotalEntries = 0;
	NET_API_STATUS nStatus;
	BOOL ret_val = TRUE;

	wchar_t* logon_svr_ptr = NULL;
	if (wdomain.length() > 0)
		logon_svr_ptr = (wchar_t*)wdomain.c_str();
	
	std::wstring wGroup(group.begin(), group.end());
	// Call the NetUserGetGroups function, specifying level 0.
	nStatus = NetGroupGetUsers(logon_svr_ptr, wGroup.c_str(),
		dwLevel, (LPBYTE*)&pBuf, dwPrefMaxLen, &dwEntriesRead, &dwTotalEntries, NULL);


	// If the call succeeds,
	if (nStatus == NERR_Success)
	{
		LPGROUP_USERS_INFO_0 pTmpBuf;
		if ((pTmpBuf = pBuf) != NULL)
		{
			// Loop through the entries; print the name of the global groups to which the user belongs.
			for (DWORD i = 0; i < dwEntriesRead; i++)
			{

				if (pTmpBuf == NULL)
				{
					DbgFprintf(outlogfile, PRINT_ERROR, "An access violation has occurred\n");
					ret_val = FALSE;
					break;
				}

				std::wstring wgroup_name(pTmpBuf->grui0_name);
				std::string user_name = ws2s(wgroup_name);
				//std::string user_name(wgroup_name.begin(), wgroup_name.end());
				user_list->push_back(user_name);

				pTmpBuf++;
			}
		}

	}
	else {
		DbgFprintf(outlogfile, PRINT_ERROR, "A system error has occurred: %d\n", nStatus);

		ret_val = FALSE;
	}

	// Free the allocated buffer.
	if (pBuf != NULL) {
		NetApiBufferFree(pBuf);
		pBuf;
	}

	
	return ret_val;

}

BOOL get_user_localgroups(std::string username, std::wstring wdomain, UserInfo* user_info)
{
	LPLOCALGROUP_USERS_INFO_0 pBuf = NULL;
	DWORD dwLevel = 0;
	DWORD dwFlags = LG_INCLUDE_INDIRECT;
	DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
	DWORD dwEntriesRead = 0;
	DWORD dwTotalEntries = 0;
	NET_API_STATUS nStatus;

	wchar_t* logon_svr_ptr = NULL;
	if (wdomain.length() > 0)
		logon_svr_ptr = (wchar_t*)wdomain.c_str();

	std::wstring wUsername(username.begin(), username.end());
	nStatus = NetUserGetLocalGroups(logon_svr_ptr, wUsername.c_str(), dwLevel, dwFlags, (LPBYTE*)&pBuf, dwPrefMaxLen, &dwEntriesRead, &dwTotalEntries);
	if (nStatus == NERR_Success)
	{
		LPLOCALGROUP_USERS_INFO_0 pTmpBuf;
		DWORD i;
		DWORD dwTotalCount = 0;

		if ((pTmpBuf = pBuf) != NULL)
		{
			// Loop through the entries
			for (i = 0; i < dwEntriesRead; i++)
			{

				if (pTmpBuf == NULL)
				{
					DbgFprintf(outlogfile, PRINT_ERROR, "An access violation has occurred\n");
					break;
				}

				//wprintf(L"\t-- %s\n", pTmpBuf->lgrui0_name);
				std::wstring wgroup_name(pTmpBuf->lgrui0_name);
				std::string group_name = ws2s(wgroup_name);
				//std::string group_name(wgroup_name.begin(), wgroup_name.end());
				user_info->AddGroup(group_name);

				pTmpBuf++;
				dwTotalCount++;
			}
		}
	}
	else {
		DbgFprintf(outlogfile, PRINT_ERROR, "\n [-] Unable to get local groups for user: Error: %d\n", nStatus);
		return FALSE;
	}
	
	//Free memory
	if (pBuf != NULL)
		NetApiBufferFree(pBuf);

	return TRUE;
}

BOOL get_users_in_localgroup(std::string group, std::wstring wdomain, std::vector<std::string> *user_list) {

	LPLOCALGROUP_MEMBERS_INFO_1 pBuf;
	DWORD dwLevel = 1;
	DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
	DWORD dwEntriesRead = 0;
	DWORD dwTotalEntries = 0;
	NET_API_STATUS nStatus;
	BOOL ret_val = TRUE;

	wchar_t* logon_svr_ptr = NULL;
	if (wdomain.length() > 0)
		logon_svr_ptr = (wchar_t*)wdomain.c_str();
	
	std::wstring wGroup(group.begin(), group.end());

	//Check if the logonserver is the current computer
	nStatus = NetLocalGroupGetMembers(logon_svr_ptr, wGroup.c_str(),
			dwLevel, (LPBYTE*)&pBuf, dwPrefMaxLen, &dwEntriesRead, &dwTotalEntries, NULL);

	// If the call succeeds,
	if (nStatus == NERR_Success)
	{
		LPLOCALGROUP_MEMBERS_INFO_1 pTmpBuf;
		if ((pTmpBuf = pBuf) != NULL)
		{
			// Loop through the entries; print the name of the global groups to which the user belongs.
			for (DWORD i = 0; i < dwEntriesRead; i++)
			{

				if (pTmpBuf == NULL)
				{
					DbgFprintf(outlogfile, PRINT_ERROR, "An access violation has occurred\n");
					ret_val = FALSE;
					break;
				}

				std::wstring wgroup_name(pTmpBuf->lgrmi1_name);
				std::string user_name = ws2s(wgroup_name);
				//std::string user_name(wgroup_name.begin(), wgroup_name.end());
				user_list->push_back(user_name);

				pTmpBuf++;
			}
		}

	}
	else {
		DbgFprintf(outlogfile, PRINT_ERROR, "A system error has occurred: %d\n", nStatus);
		ret_val = FALSE;
	}

	// Free the allocated buffer.
	if (pBuf != NULL) {
		NetApiBufferFree(pBuf);
		pBuf;
	}

	return ret_val;

}

BOOL get_user_info(std::string username, UserInfo *user_info) {

	LPUSER_INFO_1 pBuf = NULL;

	//DWORD i;
	DWORD dwTotalCount = 0;
	LPTSTR pszServerName = NULL;
	NET_API_STATUS nStatus;
	BOOL ret_val = TRUE;

	wchar_t* logon_srv_var = NULL;
	if (get_domain_controller(&logon_srv_var) == FALSE)
		return FALSE;

	// Call the NetUserGetGroups function, specifying level 0.
	std::wstring wUsername(username.begin(), username.end());

	DWORD user_info_1 = 1;
	nStatus = NetUserGetInfo((LPCWSTR)logon_srv_var, wUsername.c_str(), user_info_1, (LPBYTE*)&pBuf);

	// If the call succeeds,
	if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA))
	{	
		//  Set the user flags.
		user_info->SetUserFlags(pBuf->usri1_flags);

		//  Set the user password age.
		user_info->SetPasswordAge(pBuf->usri1_password_age);

		std::wstring wscript_path(pBuf->usri1_script_path);
		std::string script_path = ws2s(wscript_path);
		//std::string script_path(wscript_path.begin(), wscript_path.end());
		
		//Set script path
		user_info->SetScriptPath(script_path);
				
	}
	// Otherwise, print the system error.
	else
		fprintf(stderr, "A system error has occurred: %d\n", nStatus);

	// Free the allocated buffer.
	if (pBuf != NULL)
	{
		NetApiBufferFree(pBuf);
		pBuf = NULL;
	}

	if (logon_srv_var)
		free(logon_srv_var);

	return TRUE;
}

BOOL enumerate_web_endpoints(std::string srv_str) {

	BOOL isLocal = FALSE;
	std::string app_host_config_path;
	if (srv_str.length() > 0) {

		app_host_config_path.append("\\\\");
		app_host_config_path.append(srv_str);
		app_host_config_path.append("\\c$\\");
		app_host_config_path.append("Windows\\system32\\inetsrv\\config\\applicationHost.config");

		if (srv_str.compare("localhost") == 0 || srv_str.compare("127.0.0.1") == 0)
			isLocal = TRUE;
		
		parse_iis_apphost(app_host_config_path, isLocal);	

	}
	else {
		return FALSE;
	}

	return TRUE;
}

BOOL get_domain_controller(wchar_t** domain_str) {

	NET_API_STATUS nStatus;
	BOOL ret_val = TRUE;
	wchar_t* logon_srv_var = (wchar_t*)calloc(1, 65535 * 2);
	DWORD str_len = GetEnvironmentVariableW(L"LOGONSERVER", logon_srv_var, 65535);
	if (!str_len) {

		nStatus = NetGetDCName(NULL, NULL, (LPBYTE*)&logon_srv_var);
		if (nStatus != NERR_Success) {
			ret_val = FALSE;

			//Free buffer
			if (logon_srv_var) {
				free(logon_srv_var);
				logon_srv_var = NULL;
			}

			return ret_val;
		}
		else {
			*domain_str = logon_srv_var;
		}
	}
	else {
		*domain_str = logon_srv_var;
	}


	return ret_val;
}

BOOL convert_file_to_shellcode(std::string file_path, std::string file_args, std::vector<unsigned char>** sc_bytes) {
	DONUT_CONFIG c;
	int          err;
	memset(&c, 0, sizeof(c));

	*sc_bytes = new std::vector<unsigned char>();

	// copy input file
	lstrcpyn(c.input, file_path.c_str(), DONUT_MAX_NAME - 1);

	// copy params file
	if(file_args.length() > 0)
		lstrcpyn(c.param, file_args.c_str(), DONUT_MAX_NAME - 1);
	else {
		lstrcpyn(c.param, "C:\\Windows\\System32\\svchost.exe", DONUT_MAX_NAME - 1);
	}

	// default settings
	c.inst_type = DONUT_INSTANCE_EMBED;   // file is embedded
	c.arch = DONUT_ARCH_X84;         // dual-mode (x86+amd64)
	c.bypass = DONUT_BYPASS_CONTINUE;  // continues loading even if disabling AMSI/WLDP fails
	c.format = DONUT_FORMAT_BINARY;    // default output format
	c.compress = DONUT_COMPRESS_NONE;    // compression is disabled by default
	c.entropy = DONUT_ENTROPY_DEFAULT;  // enable random names + symmetric encryption by default
	c.exit_opt = DONUT_OPT_EXIT_THREAD;  // default behaviour is to exit the thread
	c.thread = 1;                      // run entrypoint as a thread
	c.unicode = 0;                      // command line will not be converted to unicode for unmanaged DLL function

	// generate the shellcode
	err = DntCreate(&c);
	if (err != DONUT_ERROR_SUCCESS) {
		printf("  [ Error : %s\n", DntError(err));
		return FALSE;
	}

	//Insert the shellcode
	std::vector<unsigned char>* byte_ptr = *sc_bytes;
	byte_ptr->insert(byte_ptr->end(), (char *)c.pic, (char*)c.pic + c.pic_len);
	DntDelete(&c);

	return TRUE;
}

std::string get_username() {

	std::string ret_str;

	char username[UNLEN + 1];
	DWORD username_len = UNLEN + 1;
	if (GetUserName(username, &username_len) == 0) {
		DbgFprintf(outlogfile, PRINT_ERROR, "GetUserName failed.\n");
		return ret_str;
	}

	return ret_str.assign(username);
}

void print_ip_config() {

	DWORD Err;

	PFIXED_INFO pFixedInfo;
	DWORD FixedInfoSize = 0;

	PIP_ADAPTER_INFO pAdapterInfo, pAdapt;
	DWORD AdapterInfoSize;
	PIP_ADDR_STRING pAddrStr;

	UINT i;

	struct tm newtime;
	char buffer[32];
	errno_t error;

	DebugFprintf(outlogfile, PRINT_ERROR, "\n[*] Printing Network Configuration.\n");

	// Get the main IP configuration information for this machine using a FIXED_INFO structure
	if ((Err = GetNetworkParams(NULL, &FixedInfoSize)) != 0)
	{
		if (Err != ERROR_BUFFER_OVERFLOW)
		{
			printf("GetNetworkParams sizing failed with error %d\n", Err);
			return;
		}
	}

	// Allocate memory from sizing information
	if ((pFixedInfo = (PFIXED_INFO)GlobalAlloc(GPTR, FixedInfoSize)) == NULL)
	{
		printf("Memory allocation error\n");
		return;
	}

	if ((Err = GetNetworkParams(pFixedInfo, &FixedInfoSize)) == 0)
	{
		printf("\tHost Name . . . . . . . . . : %s\n", pFixedInfo->HostName);
		printf("\tDNS Servers . . . . . . . . : %s\n", pFixedInfo->DnsServerList.IpAddress.String);
		pAddrStr = pFixedInfo->DnsServerList.Next;
		while (pAddrStr)
		{
			printf("%51s\n", pAddrStr->IpAddress.String);
			pAddrStr = pAddrStr->Next;
		}

		printf("\tNode Type . . . . . . . . . : ");
		switch (pFixedInfo->NodeType)
		{
		case 1:
			printf("%s\n", "Broadcast");
			break;
		case 2:
			printf("%s\n", "Peer to peer");
			break;
		case 4:
			printf("%s\n", "Mixed");
			break;
		case 8:
			printf("%s\n", "Hybrid");
			break;
		default:
			printf("\n");
		}

		printf("\tNetBIOS Scope ID. . . . . . : %s\n", pFixedInfo->ScopeId);
		printf("\tIP Routing Enabled. . . . . : %s\n", (pFixedInfo->EnableRouting ? "yes" : "no"));
		printf("\tWINS Proxy Enabled. . . . . : %s\n", (pFixedInfo->EnableProxy ? "yes" : "no"));
		printf("\tNetBIOS Resolution Uses DNS : %s\n", (pFixedInfo->EnableDns ? "yes" : "no"));
	}
	else
	{
		printf("GetNetworkParams failed with error %d\n", Err);
		return;
	}

	//
	// Enumerate all of the adapter specific information using the IP_ADAPTER_INFO structure.
	// Note:  IP_ADAPTER_INFO contains a linked list of adapter entries.
	//
	AdapterInfoSize = 0;
	if ((Err = GetAdaptersInfo(NULL, &AdapterInfoSize)) != 0)
	{
		if (Err != ERROR_BUFFER_OVERFLOW)
		{
			printf("GetAdaptersInfo sizing failed with error %d\n", Err);
			return;
		}
	}

	// Allocate memory from sizing information
	if ((pAdapterInfo = (PIP_ADAPTER_INFO)GlobalAlloc(GPTR, AdapterInfoSize)) == NULL)
	{
		printf("Memory allocation error\n");
		return;
	}

	// Get actual adapter information
	if ((Err = GetAdaptersInfo(pAdapterInfo, &AdapterInfoSize)) != 0)
	{
		printf("GetAdaptersInfo failed with error %d\n", Err);
		return;
	}

	pAdapt = pAdapterInfo;

	while (pAdapt)
	{
		switch (pAdapt->Type)
		{
		case MIB_IF_TYPE_ETHERNET:
			printf("\nEthernet adapter ");
			break;
		case MIB_IF_TYPE_TOKENRING:
			printf("\nToken Ring adapter ");
			break;
		case MIB_IF_TYPE_FDDI:
			printf("\nFDDI adapter ");
			break;
		case MIB_IF_TYPE_PPP:
			printf("\nPPP adapter ");
			break;
		case MIB_IF_TYPE_LOOPBACK:
			printf("\nLoopback adapter ");
			break;
		case MIB_IF_TYPE_SLIP:
			printf("\nSlip adapter ");
			break;
		case MIB_IF_TYPE_OTHER:
		default:
			printf("\nOther adapter ");
		}
		printf("%s:\n\n", pAdapt->AdapterName);

		printf("\tDescription . . . . . . . . : %s\n", pAdapt->Description);

		printf("\tPhysical Address. . . . . . : ");

		for (i = 0; i < pAdapt->AddressLength; i++)
		{
			if (i == (pAdapt->AddressLength - 1))
				printf("%.2X\n", (int)pAdapt->Address[i]);
			else
				printf("%.2X-", (int)pAdapt->Address[i]);
		}

		printf("\tDHCP Enabled. . . . . . . . : %s\n", (pAdapt->DhcpEnabled ? "yes" : "no"));

		pAddrStr = &(pAdapt->IpAddressList);
		while (pAddrStr)
		{
			printf("\tIP Address. . . . . . . . . : %s\n", pAddrStr->IpAddress.String);
			printf("\tSubnet Mask . . . . . . . . : %s\n", pAddrStr->IpMask.String);
			pAddrStr = pAddrStr->Next;
		}

		printf("\tDefault Gateway . . . . . . : %s\n", pAdapt->GatewayList.IpAddress.String);
		pAddrStr = pAdapt->GatewayList.Next;
		while (pAddrStr)
		{
			printf("%51s\n", pAddrStr->IpAddress.String);
			pAddrStr = pAddrStr->Next;
		}

		printf("\tDHCP Server . . . . . . . . : %s\n", pAdapt->DhcpServer.IpAddress.String);
		printf("\tPrimary WINS Server . . . . : %s\n", pAdapt->PrimaryWinsServer.IpAddress.String);
		printf("\tSecondary WINS Server . . . : %s\n", pAdapt->SecondaryWinsServer.IpAddress.String);

		// Display coordinated universal time - GMT 
#ifdef WIN64
		error = _localtime64_s(&newtime, &pAdapt->LeaseObtained);
#else
		time_t* time_inst = &pAdapt->LeaseObtained;
		error = _localtime32_s(&newtime, (const __time32_t*)time_inst);
#endif 
		if (error)
		{
			printf("Invalid Argument to _localtime32_s.");
		}
		else {
			// Convert to an ASCII representation 
			error = asctime_s(buffer, 32, &newtime);
			if (error)
			{
				printf("Invalid Argument to asctime_s.");
			}
			else {
				printf("\tLease Obtained. . . . . . . : %s", buffer);
			}
		}

#ifdef WIN64
		error = _localtime64_s(&newtime, &pAdapt->LeaseExpires);
#else
		time_t* time_inst2 = &pAdapt->LeaseExpires;
		error = _localtime32_s(&newtime, (const __time32_t*)time_inst2);
#endif 
		if (error)
		{
			printf("Invalid Argument to _localtime32_s.");
		}
		else {
			// Convert to an ASCII representation 
			error = asctime_s(buffer, 32, &newtime);
			if (error)
			{
				printf("Invalid Argument to asctime_s.");
			}
			else {
				printf("\tLease Expires . . . . . . . : %s", buffer);
			}
		}

		pAdapt = pAdapt->Next;
	}
}
