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

#include "wmi_tcpconn.h"
#include "wmi_utils.h"

#include <comutil.h>  // _b_str


/****************************************************************************
 * Utility functions
 */

std::string tcpStateToString(int state)
{
	switch (state) {
	case 1:
		return "CLOSED";
	case 2:
		return "LISTENING";
	case 3:
		return "SYN_SENT";
	case 4:
		return "SYN_RECEIVED";
	case 5:
		return "ESTABLISHED";
	case 6:
		return "FIN_WAIT1";
	case 7:
		return "FIN_WAIT2";
	case 8:
		return "CLOSE_WAIT";
	case 9:
		return "CLOSING";
	case 10:
		return "LAST_ACK";
	case 11:
		return "TIME_WAIT";
	case 12:
		return "DELETE_TCB";
	default:
		// printf("testing: %d\n", state);
		return "";
	}
}

void list_tcp_connections(IWbemServices* pSvc, COAUTHIDENTITY* authIdent)
{
	HRESULT hres;

	if (!pSvc)
		return;

	IEnumWbemClassObject* pEnumerator = NULL;
	hres = pSvc->ExecQuery(bstr_t("WQL"), bstr_t("SELECT * FROM MSFT_NetTCPConnection"), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
	if (FAILED(hres)) {
		printf("Query for MSFT_NetTCPConnection failed. Error code = 0x%x\n", hres);
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

	std::string tcpList = "\t    PROTO  Local Address               Foreign Address             State           PID\n";
	IWbemClassObject* pclsObj = NULL;
	ULONG uReturn = 0;
	while (pEnumerator) {
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
		if (0 == uReturn || !pclsObj) {
			break;
		}
		tcpList += "\t    TCP    ";

		VARIANT vtProp;
		std::string optionStr = "";

		// local address and port
		hr = pclsObj->Get(L"LocalAddress", 0, &vtProp, 0, 0);
		if (!FAILED(hr)) {
			optionStr += ConvertBSTRToMBS(vtProp.bstrVal);
		}
		VariantClear(&vtProp);
		hr = pclsObj->Get(L"LocalPort", 0, &vtProp, 0, 0);
		if (!FAILED(hr)) {
			optionStr += ":" + std::to_string(vtProp.intVal);
		}
		VariantClear(&vtProp);
		tcpList += fixedStrLen(optionStr, 28);

		// remote address and port
		hr = pclsObj->Get(L"RemoteAddress", 0, &vtProp, 0, 0);
		if (!FAILED(hr)) {
			optionStr += ConvertBSTRToMBS(vtProp.bstrVal);
		}
		VariantClear(&vtProp);
		hr = pclsObj->Get(L"RemotePort", 0, &vtProp, 0, 0);
		if (!FAILED(hr)) {
			optionStr += ":" + std::to_string(vtProp.intVal);
		}
		VariantClear(&vtProp);
		tcpList += fixedStrLen(optionStr, 28);

		// connection state
		hr = pclsObj->Get(L"State", 0, &vtProp, 0, 0);
		if (!FAILED(hr)) {
			optionStr += tcpStateToString(vtProp.intVal);
		}
		VariantClear(&vtProp);
		tcpList += fixedStrLen(optionStr, 16);

		hr = pclsObj->Get(L"OwningProcess", 0, &vtProp, 0, 0);
		if (!FAILED(hr)) {
			tcpList += std::to_string(vtProp.intVal);
		}
		VariantClear(&vtProp);

		pclsObj->Release();
		tcpList += "\n";
	}

	if (pEnumerator)
		pEnumerator->Release();

	if (tcpList.size() > 0) {
		printf("\t[+] WMI Netstat\n%s", tcpList.c_str());
	}
}
