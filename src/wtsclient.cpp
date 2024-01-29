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

#include <windows.h>
#include <wtsapi32.h>
#include <sstream>
#include <iomanip>

#include "wtsclient.h"
#include "debug.h"

std::string WTSClient::GetProtocol() {

	std::string proto_str;
	short proto_val = this->protocol;
	switch (proto_val) {
		case WTS_PROTOCOL_TYPE_CONSOLE:
			proto_str = "Console";
			break;
		case WTS_PROTOCOL_TYPE_ICA:
			proto_str = "ICA Protocol";
			break;
		case WTS_PROTOCOL_TYPE_RDP:
			proto_str = "RDP";
			break;
		default:
			proto_str = "Unknown";
	}
	//printf("[+] Protocol: %s\n", proto_str_ptr);
	return proto_str;
}

std::string WTSClient::GetState() {

	std::string state_str;
	short proto_val = this->state;
	switch (proto_val) {
		case WTSActive:
			state_str = "Active";
			break;
		case WTSDisconnected:
			state_str = "Disc";
			break;
		case WTSIdle:
			state_str = "Idle";
			break;
		default:
			state_str = "Other";
	}
	//printf("[+] State: %s\n", state_str);
	return state_str;
}

std::string WTSClient::GetFQDN() {
	std::string fqdn;
	if (this->domain.length() > 0) {
		fqdn.append(this->domain);
		fqdn.append("\\");
	}

	if (this->username.length() > 0) {
		fqdn.append(username);
	}

	return fqdn;
}

std::string WTSClient::toString() {
	std::stringstream ss;
	ss << std::left << std::setw(5) << this->id << std::setw(13) << this->session_name 
		<< std::setw(36) << this->GetFQDN() << std::setw(10) << this->GetState()
		<< std::setw(14) << this->GetProtocol() << std::setw(16) << this->client_addr << std::endl;
	return ss.str();
}

WTSClient::WTSClient(unsigned int id) {
	this->id = id;
	this->protocol = 0;
	this->state = 0;
}


BOOL get_sessions(std::string comp, std::vector<WTSClient*>* wtsclient_list) {

	HANDLE srv_handle = WTSOpenServerEx((LPSTR)comp.c_str());
	if (!srv_handle) {
		return FALSE;
	}

	DWORD rsv = 1;
	DWORD ret_count = 0;
	PWTS_SESSION_INFO_1 session_ptr = NULL;
	if (!WTSEnumerateSessionsEx(srv_handle, &rsv, 0, &session_ptr, &ret_count)) {
		DbgFprintf(outlogfile, PRINT_ERROR, "[-] Unable to enumerate sessions. Ensure the following reg key is set on the target system.\n[-] HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\AllowRemoteRPC=1\n");
		return FALSE;
	}

	for (DWORD i = 0; i < ret_count; i++) {

		WTS_SESSION_INFO_1 si = session_ptr[i];
		WTSClient* aClient = new WTSClient(si.SessionId);

		//Set the state of the connection
		aClient->SetState(si.State);

		//Set the session name
		if (si.pSessionName)
			aClient->SetSessionName(si.pSessionName);

		DWORD ret_size = 0;
		char* proto_type;
		if (WTSQuerySessionInformation(srv_handle, si.SessionId, WTSClientProtocolType, &proto_type, &ret_size)) {

			if (ret_size > 0)
				//Set the protocol
				aClient->SetProtocol(*proto_type);

			//Free memory
			WTSFreeMemory(proto_type);
		}
		else {
			DbgFprintf(outlogfile, PRINT_ERROR, "[-] WTSQuerySessionInformation Failed For WTSClientProtocolType.\n");
		}

		//Add domain if it's set
		if (si.pDomainName)
			aClient->SetDomain(si.pDomainName);

		//Set username if it's set
		if (si.pUserName)
			aClient->SetUsername(si.pUserName);


		char* remote_host_buf;
		if (WTSQuerySessionInformation(srv_handle, si.SessionId, WTSClientAddress, &remote_host_buf, &ret_size)) {
			if (ret_size > 0) {
				WTS_CLIENT_ADDRESS* pAddr = (WTS_CLIENT_ADDRESS*)remote_host_buf;
				if (pAddr->AddressFamily == AF_INET) {
					char* client_addr_buf = (char*)calloc(1, 20);
					if (client_addr_buf) {
						sprintf_s(client_addr_buf, 20, "%u.%u.%u.%u", pAddr->Address[2], pAddr->Address[3], pAddr->Address[4], pAddr->Address[5]);
						//printf("[+] Connection Family: %d\n", pAddr->AddressFamily);

						//Set client address
						aClient->SetClientAddress(client_addr_buf);
						//Free memory
						free(client_addr_buf);
					}
				}
			}
			WTSFreeMemory(remote_host_buf);
		}
		else {
			DbgFprintf(outlogfile, PRINT_ERROR, "[-] WTSQuerySessionInformation Failed\n");
		}

		//Add client to list
		wtsclient_list->push_back(aClient);
	}

	if (srv_handle)
		WTSCloseServer(srv_handle);

	return TRUE;

}