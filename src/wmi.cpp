#include "wmi.h"
#include "wmi/wmi_utils.h"
#include "wmi/wmi_tcpconn.h"
#include "wmi/wmi_exec.h"
#include "wmi/wmi_ps.h"

//#include <Wbemidl.h>
//#include <stdio.h>
//#include <comutil.h>
//#include <strsafe.h> //StringCchCopy, swprintf_s
//#include <string>
//#include <vector>

#pragma comment(lib, "wbemuuid.lib")


void wmi_netstat(std::string host, std::string domain, std::string user, std::string pwd)
{
	IWbemLocator* pLoc = NULL;
	IWbemServices* pCimSvc = NULL;
	COAUTHIDENTITY* authIdent = NULL;

	wchar_t* whost = NULL;
	wchar_t* wdomain = NULL;
	wchar_t* wuser = NULL;
	wchar_t* wpwd = NULL;

	if(host.size() > 0)
		whost = convertMultiByteToWide((char*)host.c_str());

	if(domain.size() > 0)
		wdomain = convertMultiByteToWide((char*)domain.c_str());

	if (user.size() > 0)
		wuser = convertMultiByteToWide((char*)user.c_str());

	if (pwd.size() > 0)
		wpwd = convertMultiByteToWide((char*)pwd.c_str());

	init_com(&pLoc);
	basic_conn(pLoc, &pCimSvc, &authIdent, whost, (wchar_t*)L"root\\standardcimv2", wdomain, wuser, wpwd);
	list_tcp_connections(pCimSvc, authIdent);

	// cleanup WMI COM resources
	if (authIdent) {
		if (authIdent->User)
			free(authIdent->User);
		if (authIdent->Domain)
			free(authIdent->Domain);
		if (authIdent->Password)
			free(authIdent->Password);

		free(authIdent);
	}
	if (pCimSvc)
		pCimSvc->Release();
	if (pLoc)
		pLoc->Release();
	CoUninitialize();

	// cleanup arguments
	if (whost)
		free(whost);
	if (wdomain)
		free(wdomain);
	if (wuser)
		free(wuser);
	if (wpwd)
		free(wpwd);
}

void wmi_exec(std::string host, std::string domain, std::string user, std::string pwd, std::string cmd)
{
	IWbemLocator* pLoc = NULL;
	IWbemServices* pCimSvc = NULL;
	COAUTHIDENTITY* authIdent = NULL;

	wchar_t* whost = NULL;
	wchar_t* wdomain = NULL;
	wchar_t* wuser = NULL;
	wchar_t* wpwd = NULL;

	if (host.size() > 0)
		whost = convertMultiByteToWide((char*)host.c_str());

	if (domain.size() > 0)
		wdomain = convertMultiByteToWide((char*)domain.c_str());

	if (user.size() > 0)
		wuser = convertMultiByteToWide((char*)user.c_str());

	if (pwd.size() > 0)
		wpwd = convertMultiByteToWide((char*)pwd.c_str());

	init_com(&pLoc);
	basic_conn(pLoc, &pCimSvc, &authIdent, whost, NULL, wdomain, wuser, wpwd);
	wmi_exec_cmd(pCimSvc, authIdent, cmd);

	// cleanup WMI COM resources
	if (authIdent) {
		if (authIdent->User)
			free(authIdent->User);
		if (authIdent->Domain)
			free(authIdent->Domain);
		if (authIdent->Password)
			free(authIdent->Password);

		free(authIdent);
	}
	if (pCimSvc)
		pCimSvc->Release();
	if (pLoc)
		pLoc->Release();
	CoUninitialize();

	// cleanup arguments
	if (whost)
		free(whost);
	if (wdomain)
		free(wdomain);
	if (wuser)
		free(wuser);
	if (wpwd)
		free(wpwd);
}

void wmi_ps(std::string host, std::string domain, std::string user, std::string pwd)
{
	IWbemLocator* pLoc = NULL;
	IWbemServices* pCimSvc = NULL;
	COAUTHIDENTITY* authIdent = NULL;

	wchar_t* whost = NULL;
	wchar_t* wdomain = NULL;
	wchar_t* wuser = NULL;
	wchar_t* wpwd = NULL;

	if (host.size() > 0)
		whost = convertMultiByteToWide((char*)host.c_str());

	if (domain.size() > 0)
		wdomain = convertMultiByteToWide((char*)domain.c_str());

	if (user.size() > 0)
		wuser = convertMultiByteToWide((char*)user.c_str());

	if (pwd.size() > 0)
		wpwd = convertMultiByteToWide((char*)pwd.c_str());

	init_com(&pLoc);
	basic_conn(pLoc, &pCimSvc, &authIdent, whost, NULL, wdomain, wuser, wpwd);
	list_wmi_processes(pCimSvc, authIdent);

	// cleanup WMI COM resources
	if (authIdent) {
		if (authIdent->User)
			free(authIdent->User);
		if (authIdent->Domain)
			free(authIdent->Domain);
		if (authIdent->Password)
			free(authIdent->Password);

		free(authIdent);
	}
	if (pCimSvc)
		pCimSvc->Release();
	if (pLoc)
		pLoc->Release();
	CoUninitialize();

	// cleanup arguments
	if (whost)
		free(whost);
	if (wdomain)
		free(wdomain);
	if (wuser)
		free(wuser);
	if (wpwd)
		free(wpwd);
}
