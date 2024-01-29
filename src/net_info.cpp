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
#include <tcpmib.h>
#include <stdio.h>
#include <iphlpapi.h>

#include "net_info.h"
#include "debug.h"

#pragma comment(lib, "iphlpapi.lib")

typedef struct _MIB_TCP6ROW_OWNER_MODULE {
	UCHAR         ucLocalAddr[16];
	DWORD         dwLocalScopeId;
	DWORD         dwLocalPort;
	UCHAR         ucRemoteAddr[16];
	DWORD         dwRemoteScopeId;
	DWORD         dwRemotePort;
	DWORD         dwState;
	DWORD         dwOwningPid;
	LARGE_INTEGER liCreateTimestamp;
	ULONGLONG     OwningModuleInfo[TCPIP_OWNING_MODULE_SIZE];
} MIB_TCP6ROW_OWNER_MODULE, *PMIB_TCP6ROW_OWNER_MODULE;

typedef struct _MIB_UDP6ROW_OWNER_MODULE {
	UCHAR         ucLocalAddr[16];
	DWORD         dwLocalScopeId;
	DWORD         dwLocalPort;
	DWORD         dwOwningPid;
	LARGE_INTEGER liCreateTimestamp;
	union {
		struct {
			int SpecificPortBind : 1;
		};
		int    dwFlags;
	};
	ULONGLONG     OwningModuleInfo[TCPIP_OWNING_MODULE_SIZE];
} MIB_UDP6ROW_OWNER_MODULE, *PMIB_UDP6ROW_OWNER_MODULE;

typedef struct _MIB_TCP6TABLE_OWNER_MODULE {
	DWORD                    dwNumEntries;
	MIB_TCP6ROW_OWNER_MODULE table[ANY_SIZE];
} MIB_TCP6TABLE_OWNER_MODULE, *PMIB_TCP6TABLE_OWNER_MODULE;

typedef struct {
	DWORD                    dwNumEntries;
	MIB_UDP6ROW_OWNER_MODULE table[ANY_SIZE];
} MIB_UDP6TABLE_OWNER_MODULE, *PMIB_UDP6TABLE_OWNER_MODULE;


BOOL get_tcp_info(std::unordered_map<size_t, ProcessInfo *> *proc_info_map)
{
	BOOL ret_val = TRUE;
	MIB_TCPTABLE_OWNER_MODULE  * tablev4 = NULL;
	MIB_TCP6TABLE_OWNER_MODULE * tablev6 = NULL;
	MIB_TCPROW_OWNER_MODULE  * currentv4 = NULL;
	MIB_TCP6ROW_OWNER_MODULE * currentv6 = NULL;
	DWORD i, state, dwSize;
	char list_port_str[40];
	unsigned short port;
	struct in_addr addr;
	std::unordered_map<size_t, ProcessInfo *>::iterator proc_it;

	// IPv4 part
	dwSize = 0;
	if (GetExtendedTcpTable(NULL, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_MODULE_ALL, 0) == ERROR_INSUFFICIENT_BUFFER) {
		
		tablev4 = (MIB_TCPTABLE_OWNER_MODULE *)malloc(dwSize);

		if (GetExtendedTcpTable(tablev4, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_MODULE_ALL, 0) == NO_ERROR) {
				
			for (i = 0; i < tablev4->dwNumEntries; i++) {
	
				currentv4 = &tablev4->table[i];

				//Get the process from the map
				proc_it = proc_info_map->find(currentv4->dwOwningPid);
				if (proc_it != proc_info_map->end()) {

					//Get pid, process info pair
					std::pair<size_t, ProcessInfo *> proc_pair = *proc_it;
					ProcessInfo * proc_info_inst = proc_pair.second;

					state = currentv4->dwState;
					if ((state <= 0) || (state > 12))
						state = 13; // points to UNKNOWN in the state array

					if (state == MIB_TCP_STATE_LISTEN) {
						port = ntohs((u_short)(currentv4->dwLocalPort & 0x0000ffff));
						memset(list_port_str, 0, sizeof(list_port_str));
						_snprintf_s(list_port_str, sizeof(list_port_str) - 1, "TCP4:%d", port);

						//Add to the proc object
						proc_info_inst->AddOpenPort(list_port_str);
					}
					else if (state == MIB_TCP_STATE_ESTAB) {
						port = ntohs((u_short)(currentv4->dwRemotePort & 0x0000ffff));
						memset(list_port_str, 0, sizeof(list_port_str));
						addr.s_addr = (long)currentv4->dwRemoteAddr;
						_snprintf_s(list_port_str, sizeof(list_port_str) - 1, "%s:%d", inet_ntoa(addr), port);
						
						//Add to the proc object
						proc_info_inst->AddOpenPort(list_port_str);
					}

				}
				
			}
		}
		else { 
			DbgFprintf(outlogfile, PRINT_ERROR, "Unable to tcpv4 table. Error: %d.\n", GetLastError());
			ret_val = FALSE;
		}
		if (tablev4)
			free(tablev4);
	}

	// IPv6 part
	dwSize = 0;
	if (GetExtendedTcpTable(NULL, &dwSize, TRUE, AF_INET6, TCP_TABLE_OWNER_MODULE_ALL, 0) == ERROR_INSUFFICIENT_BUFFER) {
		
		tablev6 = (MIB_TCP6TABLE_OWNER_MODULE *)malloc(dwSize);

		if (GetExtendedTcpTable(tablev6, &dwSize, TRUE, AF_INET6, TCP_TABLE_OWNER_MODULE_ALL, 0) == NO_ERROR) {
			
			for (i = 0; i < tablev6->dwNumEntries; i++) {
				// check available memory and allocate if necessary
				currentv6 = &tablev6->table[i];

				//Get the process from the map
				proc_it = proc_info_map->find(currentv6->dwOwningPid);
				if (proc_it != proc_info_map->end()) {

					//Get pid, process info pair
					std::pair<size_t, ProcessInfo *> proc_pair = *proc_it;
					ProcessInfo * proc_info_inst = proc_pair.second;

					state = currentv6->dwState;
					if ((state <= 0) || (state > 12))
						state = 13; // points to UNKNOWN in the state array

					if (state == MIB_TCP_STATE_LISTEN) {
						port = ntohs((u_short)(currentv6->dwLocalPort & 0x0000ffff));
						memset(list_port_str, 0, sizeof(list_port_str));
						_snprintf_s(list_port_str, sizeof(list_port_str) - 1, "TCP6:%d", port);

						//Add to the proc object
						proc_info_inst->AddOpenPort(list_port_str);
					}
					else if (state == MIB_TCP_STATE_ESTAB) {
						port = ntohs((u_short)(currentv6->dwRemotePort & 0x0000ffff));
						memset(list_port_str, 0, sizeof(list_port_str));
						_snprintf_s(list_port_str, sizeof(list_port_str) - 1, "IPV6:%d", port);

						//Add to the proc object
						proc_info_inst->AddOpenPort(list_port_str);
					}

				}
		
			}
		}
		else { // gett failed
			DbgFprintf(outlogfile, PRINT_ERROR, "Unable to tcpv6 table. Error: %d.\n", GetLastError());
			ret_val = FALSE;
		}
		if (tablev6)
			free(tablev6);
	}

	return ret_val;
}


BOOL get_udp_info(std::unordered_map<size_t, ProcessInfo *> *proc_info_map)
{
	BOOL ret_val = TRUE;
	MIB_UDPTABLE_OWNER_MODULE  * tablev4 = NULL;
	MIB_UDP6TABLE_OWNER_MODULE * tablev6 = NULL;
	MIB_UDPROW_OWNER_MODULE  * currentv4 = NULL;
	MIB_UDP6ROW_OWNER_MODULE * currentv6 = NULL;
	DWORD i, dwSize;
	char list_port_str[12];
	unsigned short listen_port;
	std::unordered_map<size_t, ProcessInfo *>::iterator proc_it;

	// IPv4 part
	dwSize = 0;
	if (GetExtendedUdpTable(NULL, &dwSize, TRUE, AF_INET, UDP_TABLE_OWNER_MODULE, 0) == ERROR_INSUFFICIENT_BUFFER) {
		
		tablev4 = (MIB_UDPTABLE_OWNER_MODULE *)malloc(dwSize);

		if (GetExtendedUdpTable(tablev4, &dwSize, TRUE, AF_INET, UDP_TABLE_OWNER_MODULE, 0) == NO_ERROR) {

			for (i = 0; i < tablev4->dwNumEntries; i++) {

				// check available memory and allocate if necessary
				currentv4 = &tablev4->table[i];

				//Get the process from the map
				proc_it = proc_info_map->find(currentv4->dwOwningPid);
				if (proc_it != proc_info_map->end()) {

					//Get pid, process info pair
					std::pair<size_t, ProcessInfo *> proc_pair = *proc_it;
					ProcessInfo * proc_info_inst = proc_pair.second;

					listen_port = ntohs((u_short)(currentv4->dwLocalPort & 0x0000ffff));
					memset(list_port_str, 0, sizeof(list_port_str));
					_snprintf_s(list_port_str, sizeof(list_port_str) - 1, "UDP4:%d", listen_port);

					//Add to the proc object
					proc_info_inst->AddOpenPort(list_port_str);

				}
		
			}
		}
		else {
			DbgFprintf(outlogfile, PRINT_ERROR, "Unable to udpv4 table. Error: %d.\n", GetLastError());
			ret_val = FALSE;
		}
		if (tablev4)
			free(tablev4);
	}


	// IPv6 part
	dwSize = 0;
	if (GetExtendedUdpTable(NULL, &dwSize, TRUE, AF_INET6, UDP_TABLE_OWNER_MODULE, 0) == ERROR_INSUFFICIENT_BUFFER) {
		
		tablev6 = (MIB_UDP6TABLE_OWNER_MODULE *)malloc(dwSize);

		if (GetExtendedUdpTable(tablev6, &dwSize, TRUE, AF_INET6, UDP_TABLE_OWNER_MODULE, 0) == NO_ERROR) {

			for (i = 0; i < tablev6->dwNumEntries; i++) {

				currentv6 = &tablev6->table[i];

				//Get the process from the map
				proc_it = proc_info_map->find(currentv6->dwOwningPid);
				if (proc_it != proc_info_map->end()) {

					//Get pid, process info pair
					std::pair<size_t, ProcessInfo *> proc_pair = *proc_it;
					ProcessInfo * proc_info_inst = proc_pair.second;

					listen_port = ntohs((u_short)(currentv6->dwLocalPort & 0x0000ffff));
					memset(list_port_str, 0, sizeof(list_port_str));
					_snprintf_s(list_port_str, sizeof(list_port_str) - 1, "UDP6:%d", listen_port);

					//Add to the proc object
					proc_info_inst->AddOpenPort(list_port_str);

				}
			
			}
		}
		else {
			DbgFprintf(outlogfile, PRINT_ERROR, "Unable to udpv6 table. Error: %d.\n", GetLastError());
			ret_val = FALSE;
		}
		if (tablev6)
			free(tablev6);
	}

	return ret_val;

}

BOOL get_network_info(std::unordered_map<size_t, ProcessInfo *> *proc_info_map)
{
	BOOL tcp_ret_val, udp_ret_val;

	tcp_ret_val = get_tcp_info(proc_info_map);
	udp_ret_val = get_udp_info(proc_info_map);
	
	return tcp_ret_val & udp_ret_val;
}
