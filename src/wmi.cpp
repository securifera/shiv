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

#include "wmi.h"
#include "wmi/wmi_utils.h"
#include "wmi/wmi_tcpconn.h"
#include "wmi/wmi_exec.h"
#include "wmi/wmi_ps.h"

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
