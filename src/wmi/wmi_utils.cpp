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

#include "wmi_utils.h"

#include <comutil.h>  // _b_str

/****************************************************************************
 * Utility functions
 */

wchar_t* convertMultiByteToWide(char* source)
{
	wchar_t* ret_str = NULL;
	if (!source)
		return ret_str;

	size_t size = mbstowcs(NULL, source, 256);
	if (size > 0) {
		ret_str = (wchar_t*)calloc(size + 1, sizeof(wchar_t));
		if (ret_str) {
			size = mbstowcs(ret_str, source, size);
			if (size == -1) {
				if (ret_str)
					free(ret_str);
				ret_str = NULL;
			}
		}
	}

	return ret_str;
}

std::string ConvertWCSToMBS(const wchar_t* pstr, long wslen)
{
	int len = WideCharToMultiByte(CP_ACP, 0, pstr, wslen, NULL, 0, NULL, NULL);

	std::string dblstr(len, '\0');
	len = WideCharToMultiByte(CP_ACP, 0, pstr, wslen, &dblstr[0], len, NULL, NULL);

	return dblstr;
}

std::string ConvertBSTRToMBS(BSTR bstr)
{
	int wslen = ::SysStringLen(bstr);
	return ConvertWCSToMBS((wchar_t*)bstr, wslen);
}

std::string fixedStrLen(std::string& inputStr, size_t fixedlen)
{
	std::string finalStr = inputStr;
	inputStr = "";

	if (finalStr.size() < fixedlen) {
		size_t num_spaces = fixedlen - finalStr.size();
		for (size_t i = 0; i < num_spaces; i++) {
			finalStr += " ";
		}
	}
	else {
		finalStr += " ";
	}
	return finalStr;
}

/****************************************************************************
 * Initialization functions
 */

#define CREDUI_MAX_USERNAME_LENGTH 128

HRESULT basic_conn(IWbemLocator* pLoc, IWbemServices** pSvc, COAUTHIDENTITY** authIdent, wchar_t* target, wchar_t* nmspace, wchar_t* domain, wchar_t* user, wchar_t* pwd)
{
	HRESULT hres;
	wchar_t resource[CREDUI_MAX_USERNAME_LENGTH + 1];

	//input validation
	if (!pLoc || !pSvc)
		return S_FALSE;

	if (authIdent)
		(*authIdent) = NULL;

	if (!nmspace)
		nmspace = (wchar_t*)L"root\\cimv2";

	if (target)
		swprintf_s(resource, (size_t)CREDUI_MAX_USERNAME_LENGTH, L"\\\\%s\\%s", target, nmspace);
	else {
		target = (wchar_t*)L".";
		swprintf_s(resource, (size_t)CREDUI_MAX_USERNAME_LENGTH, L"%s", nmspace);
	}

	// combine domain and username if needed
	//wchar_t authuser[CREDUI_MAX_USERNAME_LENGTH + 1] = { 0 };
	wchar_t* authuser = NULL;
	if (domain && user) {
		size_t domainLen = wcslen(domain);
		size_t userLen = wcslen(user);
		if (domainLen + userLen + 1 < CREDUI_MAX_USERNAME_LENGTH) {
			authuser = (wchar_t*)calloc(CREDUI_MAX_USERNAME_LENGTH + 1, sizeof(wchar_t));
			if (authuser) {
				memcpy(authuser, domain, domainLen * sizeof(wchar_t));
				authuser[domainLen] = L'\\';
				memcpy(authuser + domainLen + 1, user, userLen * sizeof(wchar_t));
			}
			else {
				// TODO handle malloc error
			}
		}
	}
	else if (user) {
		authuser = user;
	}

	hres = pLoc->ConnectServer(
		_bstr_t(resource),
		_bstr_t(authuser),    // User name
		_bstr_t(pwd),     // User password
		NULL, // Locale             
		NULL, // Security flags
		NULL, // domain        
		NULL, // Context object 
		pSvc); // IWbemServices proxy
	if (FAILED(hres)) {
		printf("[-] Could not connect to resource. Error code = 0x%x\n", hres);
		return hres;
	}

	// wprintf(L"[+] Connected to namespace: \\\\%s\\%s\n", target, nmspace);

	// initialize the security levels of the wmi connection
	if (user && pwd && authIdent) {
		// when using username and passwords (remote connections) setup the COAUTHIDENTITY
		(*authIdent) = (COAUTHIDENTITY*)calloc(sizeof(COAUTHIDENTITY), sizeof(char));
		if ((*authIdent)) {
			memset((*authIdent), 0, sizeof(COAUTHIDENTITY));

			(*authIdent)->UserLength = (ULONG)wcslen(user);
			(*authIdent)->User = (USHORT*)calloc(CREDUI_MAX_USERNAME_LENGTH + 1, sizeof(USHORT));
			if ((*authIdent)->User)
				memcpy((*authIdent)->User, user, ((*authIdent)->UserLength * sizeof(wchar_t*)));

			if (domain) {
				(*authIdent)->DomainLength = (ULONG)wcslen(domain);
				(*authIdent)->Domain = (USHORT*)calloc(CREDUI_MAX_USERNAME_LENGTH + 1, sizeof(USHORT));
				if ((*authIdent)->Domain)
					memcpy((*authIdent)->Domain, domain, ((*authIdent)->DomainLength * sizeof(wchar_t*)));
			}

			(*authIdent)->PasswordLength = (ULONG)wcslen(pwd);
			(*authIdent)->Password = (USHORT*)calloc(CREDUI_MAX_USERNAME_LENGTH + 1, sizeof(USHORT));
			if ((*authIdent)->Password)
				memcpy((*authIdent)->Password, pwd, ((*authIdent)->PasswordLength * sizeof(wchar_t*)));

			(*authIdent)->Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

			hres = CoSetProxyBlanket(
				*pSvc,                          // Indicates the proxy to set
				RPC_C_AUTHN_DEFAULT,            // RPC_C_AUTHN_xxx
				RPC_C_AUTHZ_DEFAULT,            // RPC_C_AUTHZ_xxx
				COLE_DEFAULT_PRINCIPAL,         // Server principal name 
				RPC_C_AUTHN_LEVEL_PKT_PRIVACY,  // RPC_C_AUTHN_LEVEL_xxx 
				RPC_C_IMP_LEVEL_IMPERSONATE,    // RPC_C_IMP_LEVEL_xxx
				(*authIdent),                     // client identity
				EOAC_NONE                       // proxy capabilities 
			);
		}
		else {
			// TODO handle malloc error
		}
	}
	else {
		// using current authentication context requires no special configuration
		hres = CoSetProxyBlanket(
			*pSvc,                       // Indicates the proxy to set
			RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx 
			RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx 
			NULL,                        // Server principal name 
			RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
			RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
			NULL,                        // client identity
			EOAC_NONE                    // proxy capabilities 
		);
	}

	if (FAILED(hres)) {
		printf("[-] Could not set proxy blanket. Error code = 0x%x\n", hres);
		return hres;
	}

	if (authuser)
		free(authuser);

	return hres;
}

HRESULT init_com(IWbemLocator** pLoc)
{
	HRESULT hres;

	hres = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hres)) {
		printf("Failed to initialize COM library. Error code = 0x%x\n", hres);
		return hres;
	}

	hres = CoInitializeSecurity(
		NULL,
		-1,                          // COM authentication
		NULL,                        // Authentication services
		NULL,                        // Reserved
		RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
		RPC_C_IMP_LEVEL_IDENTIFY,    // Default Impersonation  
		NULL,                        // Authentication info
		EOAC_NONE,                   // Additional capabilities 
		NULL                         // Reserved
	);
	if (FAILED(hres)) {
		printf("Failed to initialize security. Error code = 0x%x\n", hres);
		CoUninitialize();
		return hres;
	}

	hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)pLoc);
	if (FAILED(hres)) {
		printf("Failed to create IWbemLocator object. Err code = 0x%x\n", hres);
		CoUninitialize();
		return hres;
	}

	return hres;
}