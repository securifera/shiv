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

#include <winsock2.h>
#include <ws2tcpip.h>
#include <comdef.h>
#include <wsmandisp.h>
#include "wsmandisp_i.c"
#include "winrm_exec.h"
#include "debug.h"

std::string get_hostname(in_addr host) {

	char hostname[NI_MAXHOST];
	char servInfo[NI_MAXSERV];
	struct sockaddr_in saGNI;
	std::string ret_str;

	//-----------------------------------------
	// Set up sockaddr_in structure which is passed
	// to the getnameinfo function
	saGNI.sin_family = AF_INET;
	saGNI.sin_addr.s_addr = host.S_un.S_addr;

	//-----------------------------------------
	// Call getnameinfo
	DWORD dwRetval = getnameinfo((struct sockaddr *) &saGNI, sizeof(struct sockaddr), hostname, NI_MAXHOST, servInfo, NI_MAXSERV, NI_NUMERICSERV);
	if (!dwRetval)
		ret_str.assign(hostname);
	
	return ret_str;

}

BOOL winrm_exec_cmd(std::string host_ip, unsigned short port, std::string cmd, std::string user, std::string password)
{
	//Convert port to str
	char cur_port_buf[8];
	if (_itoa_s(port, cur_port_buf, sizeof(cur_port_buf) - 1, 10) != 0)
		return FALSE;
	
	HRESULT hres = NULL;
	HRESULT hr = S_OK;
	IWSManSession* pWsSess = NULL;
	IWSManConnectionOptions* options = NULL;

	//Check if we received an IP address
	in_addr buf;
	if (inet_pton(AF_INET, host_ip.c_str(), &buf) == 1) {

		//Get hostname or remote command will fail
		host_ip = get_hostname(buf);
		if (host_ip.length() == 0)
			return FALSE;

		DbgFprintf(outlogfile, PRINT_INFO3, "\tHostname: %s\n", host_ip.c_str());

	}

	// Initialize COM
	hres = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hres))
	{
		DebugFprintf(outlogfile, PRINT_ERROR, "\t[-] Failed to initialize COM library. Error: %d\n", hres);
		return FALSE; // Program has failed.
	}

	//Instatliate WSMAN COM Object
	IWSManEx* pLoc = NULL;
	hres = CoCreateInstance(CLSID_WSMan, 0, CLSCTX_INPROC_SERVER, IID_IWSMan, (LPVOID*)&pLoc);
	if (FAILED(hres))
	{
		DebugFprintf(outlogfile, PRINT_ERROR, "\tFailed to create IWSMan object. Error: %lx\n", hres);
		CoUninitialize();
		return FALSE; // Program has failed.
	}

	//Get flags
	long sess_cred_flag = 0;
	pLoc->SessionFlagCredUsernamePassword(&sess_cred_flag);

	long sess_skip_ca_flag = 0;
	hres = pLoc->SessionFlagSkipCACheck(&sess_skip_ca_flag);

	long sess_skip_cn_flag = 0;
	hres = pLoc->SessionFlagSkipCNCheck(&sess_skip_cn_flag);

	//I BELIEVE THIS FLAG IS UNNECESSARY AS THE CONNECTION DEFAULTS TO KERBEROS WITHOUT CREDS
	//long sess_use_kerb_flag = 0;
	//hres = pLoc->SessionFlagUseKerberos(&sess_use_kerb_flag);

	//Create connection options
	hres = pLoc->CreateConnectionOptions((IDispatch **)&options);
	long connection_options = sess_skip_ca_flag | sess_skip_cn_flag;

	// This needs to be fixed for supplied credentials.  Pull requests welcome...
	if (user.length() > 0 && password.length() > 0)
	{
		connection_options |= sess_cred_flag;
		options->put_UserName(_bstr_t(user.c_str()));
		options->put_Password(_bstr_t(password.c_str()));
	}

	//Build connect string
	std::string connect_str = "http://";
	connect_str.append(host_ip);
	connect_str.append(":");
	connect_str.append(cur_port_buf);
	connect_str.append("/wsman");

	//Convert to BSTR
	_bstr_t connect_bstr = _bstr_t(connect_str.c_str());

	//Create session
	hres = pLoc->CreateSession(connect_bstr, connection_options, options, (IDispatch **)&pWsSess);
	if (FAILED(hres))
	{
		DebugFprintf(outlogfile, PRINT_ERROR, "\tConnection Failed. Error: %d\n", hres);
		pLoc->Release();
		CoUninitialize();
		return FALSE; // Program has failed.
	}

	//Invoke Command
	_bstr_t command = (_bstr_t)cmd.c_str();
	_variant_t resource = "http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/Win32_Process";
	BSTR parameters = "<p:Create_INPUT xmlns:p=\"http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/Win32_Process\"><p:CommandLine>" + command + "</p:CommandLine></p:Create_INPUT>";
	BSTR response;
	hres = pWsSess->Invoke(_bstr_t("Create"), resource, parameters, 0, (BSTR *)&response);
	if( hres == 0x80338012){
		DebugFprintf(outlogfile, PRINT_ERROR, "\tEnsure WinRM service is running on remote host. Error: %lx\n", hres);
	}
	else if (hres == E_ACCESSDENIED) {
		DebugFprintf(outlogfile, PRINT_ERROR, "\tEnsure user has remote execution permissions. Error: %lx\n", hres);
	}
	else if (hres == 0x80338041) {
		DebugFprintf(outlogfile, PRINT_ERROR, "\tXML schema validation error. Error: %lx\n", hres);
	}
	else if (hres == 0x803381BB) {
		DebugFprintf(outlogfile, PRINT_ERROR, "\tDefault auth not supported. Use credentials. Error: %lx\n", hres);
	}
	else if (hres == 0x8033810c) {
		DebugFprintf(outlogfile, PRINT_ERROR, "\tKerberos cannot be used for nondomain computer. Error: %lx\n", hres);
	}
	else if (hres == 0x8007052e) {
		DebugFprintf(outlogfile, PRINT_ERROR, "\tUnknown username or bad password. Error: %lx\n", hres);
	} 
	else if (hres == 0x803380e4) {
		DebugFprintf(outlogfile, PRINT_ERROR, "\tServer not trusted. Error: %lx\n", hres);
	}
	else if(hres != 0){
		DebugFprintf(outlogfile, PRINT_ERROR, "\tExecute Error: %lx\n", hres);
	}
	else {
		DebugFprintf(outlogfile, PRINT_INFO1, "\tExecuted command: '%s'\n", cmd.c_str());
	}

	//Cleanup
	if (pWsSess)
		pWsSess->Release();
	if(options)
		options->Release();
	if (pLoc)
		pLoc->Release();
	CoUninitialize();

	return TRUE;
}