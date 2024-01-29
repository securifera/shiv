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

#include "wmi_ps.h"
#include "wmi_utils.h"

#include <comutil.h>  // _b_str


void list_wmi_processes(IWbemServices* pSvc, COAUTHIDENTITY* authIdent)
{
	HRESULT hres;

	if (!pSvc)
		return;

	IEnumWbemClassObject* pEnumerator = NULL;
	hres = pSvc->ExecQuery(bstr_t("WQL"), bstr_t("SELECT * FROM Win32_Process"), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
	if (FAILED(hres)) {
		printf("Query for Win32_Process failed. Error code = 0x%x\n", hres);
		return;
	}

	if (authIdent) {
		hres = CoSetProxyBlanket(
			pEnumerator,                    // Indicates the proxy to set
			RPC_C_AUTHN_DEFAULT,            // RPC_C_AUTHN_xxx
			RPC_C_AUTHZ_DEFAULT,            // RPC_C_AUTHZ_xxx
			COLE_DEFAULT_PRINCIPAL,         // Server principal name 
			RPC_C_AUTHN_LEVEL_PKT_PRIVACY,  // RPC_C_AUTHN_LEVEL_xxx 
			RPC_C_IMP_LEVEL_IMPERSONATE,    // RPC_C_IMP_LEVEL_xxx
			authIdent,                       // client identity
			EOAC_NONE                       // proxy capabilities 
		);
		//TODO check return
	}

	std::string outputList = "\t    NAME        PID      CommandLine\n";
	IWbemClassObject* pclsObj = NULL;
	ULONG uReturn = 0;
	while (pEnumerator) {
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
		if (0 == uReturn || !pclsObj) {
			break;
		}
		//tcpList += "\t    TCP    ";

		VARIANT vtProp;
		std::string optionStr = "";

		// Name
		hr = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
		if (!FAILED(hr)) {
			//optionStr += ConvertBSTRToMBS(vtProp.bstrVal);
			outputList += ConvertBSTRToMBS(vtProp.bstrVal);
		}
		VariantClear(&vtProp);

		// PID
		hr = pclsObj->Get(L"ProcessId", 0, &vtProp, 0, 0);
		if (!FAILED(hr)) {
			//optionStr += ":" + std::to_string(vtProp.intVal);
			outputList += " " + std::to_string(vtProp.intVal);
		}
		VariantClear(&vtProp);
		//outputList += fixedStrLen(optionStr, 28);

		// PPID
		hr = pclsObj->Get(L"ParentProcessId", 0, &vtProp, 0, 0);
		if (!FAILED(hr)) {
			//optionStr += ":" + std::to_string(vtProp.intVal);
			outputList += " " + std::to_string(vtProp.intVal);
		}
		VariantClear(&vtProp);

		// Name
		hr = pclsObj->Get(L"CommandLine", 0, &vtProp, 0, 0);
		if (!FAILED(hr)) {
			outputList += " " + ConvertBSTRToMBS(vtProp.bstrVal);
		}
		VariantClear(&vtProp);

		pclsObj->Release();
		outputList += "\n";
	}

	if (pEnumerator)
		pEnumerator->Release();

	if (outputList.size() > 0) {
		printf("\t[+] WMI Process List\n%s", outputList.c_str());
	}
}
