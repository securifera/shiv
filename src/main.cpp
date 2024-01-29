#define WIN32_LEAN_AND_MEAN

#include <ws2tcpip.h> //InetPton, getaddrinfo, 
#include <conio.h> //_kbhit
#include <vector>
#include <algorithm>
#include <set>
#include <string> //stoi
#include <thread>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <wtsapi32.h>
#include <iostream>
#include <winnetwk.h>

//Local includes
#include "getopt.h"
#include "wtsclient.h"
#include "winrm_exec.h"
#include "debug.h"
#include "utils.h"
#include "user_info.h"
#include "process_info.h"
#include "svc_info.h"
#include "net_info.h"
#include "net_share.h"
#include "wmi.h"
#include "main.h"
#include "smb/smb.h"
#include "synchapi.h"
#include "sc_exec.h"
#include "dpipe/child_process.h"

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "wtsapi32.lib")
#pragma comment (lib, "Mpr.lib")

std::atomic<int> global_timeout = 1;
std::atomic<int> global_timeout_micro = 0;
std::atomic<bool> stop_thread = false;
std::unordered_map<std::string, UserInfo *> user_info_map;
std::atomic <HANDLE> remote_token = 0;
std::string old_password;

//PORTS
#define WMI_PORT 135
#define WMI_PORT_STR "135"
#define SMB_PORT 445
#define SMB_PORT_STR "445"
#define WSMAN_PORT 5985
#define WSMAN_PORT_STR "5985"

std::mutex output_mtx;

#define PORT_BLOCK_SIZE 10
#define MAX_RETRY 3
#define KILL_THREAD_TIMEOUT 120
#define MAX_PORT 65535

#define WINRM_EXEC "winrm"
#define SMB_EXEC "smb"
#define WMI_EXEC "wmi"

void usage()
{
	printf("Usage: shiv.exe [Options...]\n\
\t-s hosts   \tHosts - can be in comma separated list, ip address, hostname, or ip address range\n\
\t-p ports   \tPorts - can be in comma separated list, single port, or hyphen seperated range\n\n\
\t-c command \tCommand - command to execute on remote host or arguments for shellcode binary\n\
\t-b type    \tExecution Type - WinRM (port 5985), SMB (445), WMI (135)\n\
\t-f path    \tExecutable Path - The local executable binary (x64) to inject into memory and execute remotely (SMB)\n\n\
\t-d domain  \tDomain - domain for remote authentication or domain controller for AD functions\n\
\t-u user    \tUser - username for remote command (i.e. joe, joe@DOMAIN) \n\
\t-P pass    \tPassword - password for user\n\
\t-o pass    \tOld Password - old password for user\n\n\
\t-g group   \tGroup - list users in group \n\
\t-t time    \tTimeout - in seconds to wait for connections\n\
\t-l log     \tLog Path - change the output to a file path or \"stdout\" \n\
\t-v val     \tVerbosity - up to three levels of verbosity\n\n\
\t-x         \tSessions - list sessions on host (port 445)\n\
\t-z         \tServer Info - list OS, hostname, domain of server via SMB (port 445)\n\
\t-n         \tChange Password - change the user's pw on the host\n\
\t-r         \tShares - list shares on hosts (port 445)\n\
\t-e         \tWeb Endpoints - list any web endpoints listed in C:\\Windows\\System32\\inetsrv\\applicationHost.xml\n\
\t-i         \tWMI netstat - list network connection info on host (port 135)\n\
\t-y         \tProcesses - list process information on current host\n\
\t-a         \tPassword Spray - attempt to login to every domain user with the given password \n\
\t-E         \tLocal enumeration - Enumerate current system. e.g. IP Address, Hostname, PATH, user \n\
\t-h         \tHelp - print this help message\n\
");

	printf("\nExample: shiv.exe -s 172.16.4.0/27,172.16.0.1 -p 135,443,500-800 -t 2\n\n");
}
/**
 * translate_iprange - takes an ip range in the form of 127.0.0.1/24 notation
 *	and return vector of each individual ip
 */
std::vector<std::string> translate_iprange(std::string iprange)
{
	std::vector<std::string> hosts;
	size_t found = std::string::npos;

	found = iprange.find('/');

	std::string ip_str = iprange.substr(0, found);
	std::string mask_str = iprange.substr(found+1, iprange.size() - found);

	IN_ADDR ipv4_addr, netmask, curr_ip;
	char buf[64];
	int ret;
	unsigned int calc_mask = 0, mask_val = 0;
	const unsigned int max_mask = UINT32_MAX, max_mask_bits = 32;

	try {
		//convert bitmask string to int
		unsigned int mask_bits = std::stoi(mask_str, nullptr, 10);

		//calculate netmask
		calc_mask = max_mask << (max_mask_bits - mask_bits);
		mask_val = max_mask - calc_mask;
		netmask.S_un.S_addr = htonl(calc_mask);

		//convert ip string to int val
		ret = InetPtonA(AF_INET, ip_str.c_str(), &ipv4_addr);
		if(ret != 1) {
			DbgFprintf(outlogfile, PRINT_ERROR, "[-] could not convert to Ipv4 address.\n");
			return hosts;
		}

		//starting from first ip, add ip to vector
		curr_ip.S_un.S_addr = netmask.S_un.S_addr & ipv4_addr.S_un.S_addr;
		int curr_ip_hostbyteorder = ntohl(curr_ip.S_un.S_addr);
		for(unsigned int i=0; i<=mask_val; i++) {
			//create string to hold ip and add it to vector
			memset(buf, 0, sizeof(buf));
			InetNtopA(AF_INET, &curr_ip, buf, sizeof(buf));
			std::string curr_ip_str(buf);
			hosts.push_back(curr_ip_str);

			//increment ip addr
			curr_ip_hostbyteorder++;
			curr_ip.S_un.S_addr = htonl(curr_ip_hostbyteorder);
		}
		
	}
	catch(std::string ex) {
		//TODO handle this????
	}

	return hosts;
}

/**
 * translate_hosts2 - second part of translating string representing hosts
 *	checks for '/' separated values and translates that into ip range
 *	non '/' containing strings are treated as single values
 */
std::vector<std::string> translate_hosts2(std::vector<std::string> input_hosts)
{
	std::vector<std::string> hosts;
	size_t found = 0;

	for(auto i : input_hosts) {
		if((found = i.find('/')) != std::string::npos) {
			//assume ip address range in 127.0.0.0/24 notation
			std::vector<std::string> translated_range = translate_iprange(i);
			hosts.insert(hosts.end(), translated_range.begin(), translated_range.end());
		}
		else {
			//single ip address or hostname
			hosts.push_back(i);
		}
	}

	return hosts;
}

/**
 * translate_hosts - first part of translating string representing hosts
 *	This function seperates strings by commas and passes those to second fucntion
 */
std::vector<std::string> translate_hosts(std::string input_hosts)
{
	std::vector<std::string> hosts;
	std::vector<std::string> hosts_raw;

	if(input_hosts.find(',') != std::string::npos) {
		//comma seperated list of hosts (172.16.4.0/24,127.0.0.1,127.0.0.2)
		size_t found_first = 0, found = 0;
		while((found = input_hosts.find(',', found)) != std::string::npos) {
			hosts_raw.push_back(input_hosts.substr(found_first, found-found_first));
			found_first = ++found;
		}
		//copy final item in list
		if(found_first < input_hosts.size()) {
			hosts_raw.push_back(input_hosts.substr(found_first));
		}
	}
	else {
		//treat as if there is only one host specified
		hosts_raw.push_back(input_hosts);
	}

	//final translation of hosts
	hosts = translate_hosts2(hosts_raw);

	return hosts;
}

/**
 * translate_portrange - hyphen seperated values are expanded out
 *	into list of ports
 */
std::vector<std::string> translate_portrange(std::string port_range)
{
	std::vector<std::string> ports;
	size_t found = std::string::npos;

	if((found = port_range.find('-')) != std::string::npos) {
		std::string start_port_str = port_range.substr(0, found);
		std::string end_port_str = port_range.substr(found+1);

		int start_port, end_port;
		start_port = atoi(start_port_str.c_str());
		end_port = atoi(end_port_str.c_str());

		// Check if start port is negative or greater than max port
		if (start_port < 0 || start_port > MAX_PORT) {
			DbgFprintf(outlogfile, PRINT_ERROR, "[-] Invalid port range: %d\n", start_port);
			return ports;
		}

		// Check if ending port is negative or greater than max port
		if (end_port < 0 || end_port > MAX_PORT || end_port < start_port) {
			DbgFprintf(outlogfile, PRINT_ERROR, "[-] Invalid port range: %d\n", end_port);
			return ports;
		}

		char cur_port_buf[8];
		for(int i=start_port; i<=end_port; i++) {
			memset(cur_port_buf, 0, sizeof(cur_port_buf));
			if(_itoa_s(i, cur_port_buf, sizeof(cur_port_buf)-1, 10) == 0) {
				ports.push_back(std::string(cur_port_buf));
			}
		}
	}

	return ports;
}

/**
 * translate_ports2 - second part of translating string representing ports
 *	checks for hyphen separated values and translates that into range
 *	non hyphenated strings are treated as single values
 */
std::vector<std::string> translate_ports2(std::vector<std::string> input_ports)
{
	std::vector<std::string> ports;
	size_t found = 0;

	for(auto i : input_ports) {
		if((found = i.find('-')) != std::string::npos) {
			//assume port range given in 135-445 notation
			std::vector<std::string> translated_range = translate_portrange(i);
			ports.insert(ports.end(), translated_range.begin(), translated_range.end());
		}
		else {
			//single ip address or hostname
			ports.push_back(i);
		}
	}

	return ports;
}

/**
 * translate_ports - first part of translating string representing ports
 *	This function seperates strings by commas and passes those to second fucntion
 *	NOTE - port numbers are kept as strings for the getaddrinfo
 */
std::vector<std::string> translate_ports(std::string input_ports)
{
	std::vector<std::string> ports;
	std::vector<std::string> ports_raw;

#ifdef _DEBUG
	clock_t begin = clock();
#endif

	if(input_ports.find(",") != std::string::npos) {
		//comma seperated list of ports (135,445,1000-3000)
		size_t found_first = 0, found = 0;
		while((found = input_ports.find(',', found)) != std::string::npos) {
			ports_raw.push_back(input_ports.substr(found_first, found-found_first));
			found_first = ++found;
		}
		//copy final item in list
		if(found_first < input_ports.size()) {
			ports_raw.push_back(input_ports.substr(found_first));
		}
	}
	else {
		//treat as if there is only one host specified
		ports_raw.push_back(input_ports);
	}

	//final translation of 
	ports = translate_ports2(ports_raw);

#ifdef _DEBUG
	clock_t end = clock();
	double elapsed = ((double)end-(double)begin) / CLOCKS_PER_SEC;
	DbgFprintf(outlogfile, PRINT_INFO3, "[*] Input port range translation time: %f seconds\n", elapsed);
#endif

	return ports;
}

/**
 * block_port_scan - actual port scanning logic. Receives hostname/ip and list of ports to scan.
 *	open ports are saved to std::set declarded outside the scope of this function.
 */
void block_port_scan(std::string host, std::vector<std::string> ports, std::set<unsigned short>* open_ports, std::mutex* open_ports_mtx)
{
	SOCKET sock = INVALID_SOCKET;
	struct addrinfo *result = NULL, *ptr = NULL, hints;
	int res;

	//socket timeout
	TIMEVAL Timeout;
	Timeout.tv_sec = global_timeout;
    Timeout.tv_usec = global_timeout_micro;

	memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

	for(auto port_str : ports) {
		//make sure thread stoppage flag isnt set
		if(stop_thread)
			break;

		// Resolve the server address and port
        // Replace with inet_pton to check if it's an IP vs a hostname
		res = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &result);
		if (res != 0) {
			DbgFprintf(outlogfile, PRINT_ERROR, "[-] getaddrinfo failed with error: %d\n", res);
			continue;
		}

		//Attempt to connect to an address until one succeeds
		for(ptr=result; ptr != NULL; ptr=ptr->ai_next) {
			int retry = 0;
			while(retry < MAX_RETRY) {
				//Create a SOCKET for connecting to server
				sock = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
				if (sock == INVALID_SOCKET) {
					DbgFprintf(outlogfile, PRINT_ERROR, "[-] socket failed with error: %ld\n", WSAGetLastError());
					retry++;
					std::this_thread::sleep_for(std::chrono::microseconds(1));
					continue;
				}

				unsigned long mode = 1;
				res = ioctlsocket(sock, FIONBIO, &mode);
				if(res != NO_ERROR) {	
					DbgFprintf(outlogfile, PRINT_ERROR, "[-] ioctlsocket failed with error: %ld\n", res);
					retry++;
					continue;
				}

				//attempt connection
				connect(sock, ptr->ai_addr, (int)ptr->ai_addrlen);

				//restart the socket mode
				mode = 0;
				res = ioctlsocket(sock, FIONBIO, &mode);
				if (res != NO_ERROR) {	
					DbgFprintf(outlogfile, PRINT_ERROR, "[-] ioctlsocket failed with error: %ld\n", res);
					retry++;
					continue;
				}

				fd_set Write, Err;
				FD_ZERO(&Write);
				FD_ZERO(&Err);
				FD_SET(sock, &Write);
				FD_SET(sock, &Err);

				//check if the socket is ready
				select(0, NULL, &Write, &Err, &Timeout);			
				if(FD_ISSET(sock, &Write)) {
					//Open port
					open_ports_mtx->lock();
					open_ports->insert(atoi(port_str.c_str()));
					open_ports_mtx->unlock();
					retry = MAX_RETRY;
				}

				closesocket(sock);
				sock = INVALID_SOCKET;
				retry++;
			}
		}

		freeaddrinfo(result);
	}
}

BOOL establish_connection(std::string server, std::string username, std::string password, bool connect)
{
	DWORD rc = 0;
	std::string remoteResource = "\\\\";
	remoteResource.append(server);
	remoteResource.append("\\C$");

	if (connect)
	{
		//Check if already connected
		HANDLE hEnum = NULL;
		if (NO_ERROR == WNetOpenEnum(RESOURCE_CONNECTED, RESOURCETYPE_ANY, 0, NULL, &hEnum))
		{
			bool bConnected = false;
			DWORD bufSize = 65536;
			BYTE *buf = (BYTE*)calloc(1, bufSize);
			if (buf == NULL)
				return false;

			DWORD count = 0;
			rc = WNetEnumResource(hEnum, &count, buf, &bufSize);
			for (DWORD i = 0; i < count; i++)
			{
				NETRESOURCE* pNR = (NETRESOURCE*)buf;
				if (0 == stricmp(pNR[i].lpRemoteName, remoteResource.c_str()))
				{
					bConnected = true;
					break;
				}
			}

			//Free memory
			if (buf)
				free(buf);

			rc = WNetCloseEnum(hEnum);
			if (bConnected)
				return true;
		}

		NETRESOURCE nr = { 0 };
		nr.dwType = RESOURCETYPE_ANY;
		nr.lpLocalName = NULL;
		nr.lpRemoteName = (LPSTR)remoteResource.c_str();
		nr.lpProvider = NULL;

		//Establish connection (using username/pwd)
		rc = WNetAddConnection2(&nr, password.c_str(), username.c_str(), 0);
		if (NO_ERROR == rc)
		{
			return true;
		}
		else
		{
			DbgFprintf(outlogfile, PRINT_ERROR, "[-] Failed to connect to %s.", remoteResource.c_str());
			return false;
		}
	}
	else
	{
		rc = WNetCancelConnection2(remoteResource.c_str(), 0, FALSE);
		return true;
	}
}

BOOL impersonate_user(std::string server, std::string user, std::string password ) {

	HANDLE temp_token;
	bool bLogonUser = LogonUser(user.c_str(), server.c_str(), password.c_str(), LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_WINNT50, &temp_token);
	if (!bLogonUser || temp_token == 0)
	{
		printf("LogonUser failed. Error: %d\n", GetLastError());
		return FALSE;
	}
	
	//If there's an old token, revert and close it first
	HANDLE old_token = remote_token.load();
	if (old_token != 0) {
		RevertToSelf();
		CloseHandle(old_token);
		remote_token.store(0);
	}

	//Impersonate Token
	if (ImpersonateLoggedOnUser(temp_token) == 0) {
		printf("ImpersonateLoggedOnUser Faield. Error: %d\n", GetLastError());
		return FALSE;
	}
		
	//Set the new token
	remote_token.store(temp_token);

	return TRUE;

}

/**
 * port_scan - breaks port list into blocks to be handles in seperate threads
 */
void port_scan(ArgConfig *arg_config_inst, std::string host, std::vector<std::string> ports)
{
	std::set<unsigned short>* open_ports = new std::set<unsigned short>();
	std::mutex* open_ports_mtx = new std::mutex();
	std::vector<std::thread*> the_threads;

	//device port list into blocks and handle in seperate threads
	size_t idx = 0;
	while(idx+PORT_BLOCK_SIZE < ports.size()) {
		try {
			// Starting and Ending iterators 
			auto start = ports.begin() + idx;
			auto end = ports.begin() + idx + PORT_BLOCK_SIZE;
			std::vector<std::string> block_ports(PORT_BLOCK_SIZE);

			// Copy vector using copy function() 
			std::copy(start, end, block_ports.begin());
			//std::vector<std::string> block_ports(&ports[idx], &ports[idx+PORT_BLOCK_SIZE]);
			try {
				std::thread* a_thread = new std::thread(block_port_scan, host, block_ports, open_ports, open_ports_mtx);
				the_threads.push_back(a_thread);
			}
			catch (const std::system_error & e) {
				std::cout << "Caught system_error with code " << e.code()
					<< " meaning " << e.what() << '\n';
				return;
			}

			idx += PORT_BLOCK_SIZE;
		}
		catch(std::system_error err) {
			//scanner_printf(ERROR_INFO, "\tPort block thread creation failure: %s\n", err.what());
			//std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}
	}
	//add any left over ports
	if(idx < ports.size()) {

		// Starting and Ending iterators 
		auto start = ports.begin() + idx;
		auto end = ports.end();
		std::vector<std::string> block_ports(ports.size() - idx);
		
		// Copy vector using copy function() 
		std::copy(start, end, block_ports.begin());
		try {
			std::thread* a_thread = new std::thread(block_port_scan, host, block_ports, open_ports, open_ports_mtx);
			the_threads.push_back(a_thread);
		}
		catch (const std::system_error & e) {
			std::cout << "Caught system_error with code " << e.code()
				<< " meaning " << e.what() << '\n';
			return;
		}
	}

	//wait for scan threads to finish
	for(auto thr : the_threads) {
		thr->join();
		delete thr;
	}

	//Get configuration values
	std::string username = arg_config_inst->GetUsr();
	std::string password = arg_config_inst->GetPw();
	std::string domain = arg_config_inst->GetDomain();


	//output results
	output_mtx.lock();
	if(open_ports->size() > 0) {
		DebugFprintf(outlogfile, PRINT_INFO1, "\n[+] Host: %s has the following ports open:\n", host.c_str());
		for(auto p : *open_ports)
			DebugFprintf(outlogfile, PRINT_INFO1, "\t[+] Port %d is open\n", p);	


		//Authenticate to the box using the passed credentials
		if( open_ports->find(SMB_PORT) != open_ports->end() && !username.empty() && !password.empty())
			establish_connection(host, username, password, true);
			
		// Get net sessions
		if (arg_config_inst->ListRemoteSessions() && open_ports->find(SMB_PORT) != open_ports->end()) {

			//Get the sessions
			std::vector<WTSClient *> wtsclient_list;
			if (get_sessions(host, &wtsclient_list)) {

				//Print the clients
				for (std::vector<WTSClient *>::iterator it = wtsclient_list.begin(); it != wtsclient_list.end(); ++it) {
					WTSClient *cur_client = *it;

					//Get username and retrieve groups they are in
					std::string cur_username = cur_client->GetUsername();
					if (cur_username.length() == 0)
						continue;

					std::unordered_map<std::string, UserInfo *>::iterator map_it;
					map_it = user_info_map.find(cur_username);
					UserInfo *user_data_inst = nullptr;

					if (map_it == user_info_map.end()) {

						user_data_inst = new UserInfo(cur_username);
						std::pair<std::string, UserInfo *> user_info_pair(cur_username, user_data_inst);
						user_info_map.insert(user_info_pair);

					}
					else {

						//Get user data
						std::pair<std::string, UserInfo *> user_pair = *map_it;
						user_data_inst = user_pair.second;

					}

					//Set user data
					user_data_inst->AddSession(std::string(host));
					user_data_inst->SetClientAddress(cur_client->GetClientAddress());
					
					delete *it;
				}
				
			}
		}

		//Execute command
		struct smb_context* smb_context_inst = NULL;
		std::string command = arg_config_inst->GetCommand();
		std::string exe_file_path = arg_config_inst->GetLocalExecutablePath();
		std::string execution_type = arg_config_inst->GetExecutionType();

		if ((command.length() > 0 || exe_file_path.length() > 0) && execution_type.length() > 0) {

			if (execution_type.compare(SMB_EXEC) == 0 && open_ports->find(SMB_PORT) != open_ports->end()) {
				smb_context_inst = get_srv_info(host);
				if (smb_context_inst != NULL) 
					sc_exec_func(host, smb_context_inst->server_hostname, command, exe_file_path);				
			}

			if (execution_type.compare(WINRM_EXEC) == 0 && open_ports->find(WSMAN_PORT) != open_ports->end())
				winrm_exec_cmd(host, WSMAN_PORT, command, username, password);

			if (execution_type.compare(WMI_EXEC) == 0 && open_ports->find(WMI_PORT) != open_ports->end()) {
				wmi_exec(host, domain, username, password, command);
			}
		}

		// Get srv info
		if (arg_config_inst->ListServerInfo() && open_ports->find(SMB_PORT) != open_ports->end()) {
			if (smb_context_inst == NULL) {
				smb_context_inst = get_srv_info(host);
				if (smb_context_inst != NULL) {
					std::string ret_str = smb_context_to_string(smb_context_inst);
					printf("\t[*] %s", ret_str.c_str());					
				}
			}
		}

		//Free smb context
		if (smb_context_inst != NULL) {
			free_smb_context(smb_context_inst);
			smb_context_inst = NULL;
		}

		// Get net shares
		if (arg_config_inst->ListRemoteShares() && open_ports->find(SMB_PORT) != open_ports->end())
			net_view(host);		

		// Get IIS web endpoints
		if (arg_config_inst->WebEnum() && open_ports->find(SMB_PORT) != open_ports->end())
			enumerate_web_endpoints(host);        
        
		// Get WMI netstat info
		if (arg_config_inst->ListRemoteNetstat() && open_ports->find(WMI_PORT) != open_ports->end())
			wmi_netstat(host, domain, username, password);

		// Get WMI process list
		if (arg_config_inst->ListWmiProcesses() && open_ports->find(WMI_PORT) != open_ports->end())
			wmi_ps(host, domain, username, password);

		//Change password
		if (arg_config_inst->ChangePw() && username.length() > 0 && password.length() > 0 && old_password.length() > 0)
			remotely_change_user_pw(host, username, old_password, password);

	}
	else {
		DebugFprintf(outlogfile, PRINT_INFO1, "[-] Host: %s has no open ports\n", host.c_str());
	}
	fflush(stdout);
	output_mtx.unlock();


	//Close any connections
	establish_connection(host, username, password, false);

	//cleanup
	delete open_ports;
	delete open_ports_mtx;
}

/**
 * monitor_host_threads - blocking thread maintaining threads for each host
 */
void monitor_host_threads(std::vector<std::thread*>& scan_threads)
{
	for(auto t : scan_threads) {
		t->join();
		delete t;
	}

	DebugFprintf(outlogfile, PRINT_INFO1, "\n[+] Scanning finished\n");
}

/**
 * start_scan - Start of main scanning logic. Initialize network, and
 *	starts threads to handle each individual host in the given list.
 *	Keeps track of execution time as well.
 */
void start_scan(ArgConfig *arg_conf_inst, std::vector<std::string> hosts, std::vector<std::string> ports)
{
	int res = 0;
	WSADATA wsaData;
	std::vector<std::thread*> host_threads;

#ifndef _DEBUG
	clock_t begin = clock();
#endif

	DebugFprintf(outlogfile, PRINT_INFO1, "[+] Scanning hosts:\n");
	for(auto t : hosts) {
		DebugFprintf(outlogfile, PRINT_INFO3, "\t%s\n", t.c_str());
	}

	//initialize winsock
	res = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (res != 0) {
		DbgFprintf(outlogfile, PRINT_ERROR, "[-] WSAStartup failed with error: %d\n", res);
        return;
    }

	//start threads for each host
	for(auto host : hosts) {
		try{
			std::thread* a_thread = new std::thread(port_scan, arg_conf_inst, host, ports);
			host_threads.push_back(a_thread);
		}
		catch (const std::system_error & e) {
			std::cout << "Caught system_error with code " << e.code()
				<< " meaning " << e.what() << '\n';
			return;
		}
	}

	//seperate thread for monitoring and cleaning host thread resources
	std::thread monitor_scan_thread(monitor_host_threads, host_threads);

	//thread and winsock cleanup
	monitor_scan_thread.join();
	WSACleanup();

	//Print remote sessions
	if (arg_conf_inst->ListRemoteSessions())
		print_session_data(user_info_map, arg_conf_inst->GetDomain());

	//If there's an old token, revert and close it first
	HANDLE old_token = remote_token.load();
	if (old_token != 0) {
		RevertToSelf();
		CloseHandle(old_token);
		remote_token.store(0);
	}

	//Clear user map
	user_info_map.clear();
		
#ifndef _DEBUG
	clock_t end = clock();
	double elapsed = (double)(end-begin) / CLOCKS_PER_SEC;
	DbgFprintf(outlogfile, PRINT_INFO1, "[*] Scan time: %f seconds\n", elapsed);
#endif
}

void process_args(ArgConfig* arg_conf_inst) {

	std::string log_path = arg_conf_inst->GetLogPath();
	if (!log_path.empty()) {

		if (log_path.compare("stdout") == 0 && outlogfile != stdout) {

			//Close file if not stdout
			if (outlogfile)
				fclose(outlogfile);

			outlogfile = stdout;
		}
		else {

			//Close file if not stdout
			if (outlogfile != stdout)
				fclose(outlogfile);

			//Open file for writing
			FILE* new_file = NULL;
			errno_t err = fopen_s(&new_file, log_path.c_str(), "w+");
			if (err) {
				DbgFprintf(outlogfile, PRINT_ERROR, "[-] Error opening log file: %d\n", err);
			}
			else {
				outlogfile = new_file;
			}
		}
	}

	// Check for group parameter
	std::string ad_group = arg_conf_inst->GetADGroup();
	if (!ad_group.empty()) {

		std::string domain = arg_conf_inst->GetDomain();
	
		std::unordered_map<std::string, std::vector<std::string>*> tmp_group_userlist_map;
		get_users_in_group_all(ad_group, domain, &tmp_group_userlist_map);

		for (std::unordered_map<std::string, std::vector<std::string>*>::iterator user_info_it = tmp_group_userlist_map.begin();
			user_info_it != tmp_group_userlist_map.end(); ++user_info_it) {

			std::string cur_group = user_info_it->first;
			DebugFprintf(outlogfile, PRINT_INFO1, "%s,", cur_group.c_str());

			std::vector<std::string> *user_list = user_info_it->second;

			if (user_list->size() > 0) {
				DebugFprintf(outlogfile, PRINT_INFO1, "\"");
				for (std::vector<std::string>::iterator users_it = user_list->begin();
					users_it != user_list->end(); ++users_it) {

					std::string cur_user = *users_it;
					DebugFprintf(outlogfile, PRINT_INFO1, "%s,", cur_user.c_str());
				}
				DebugFprintf(outlogfile, PRINT_INFO1, "\"");
			}

			DebugFprintf(outlogfile, PRINT_INFO1, "\n");

		}

		return;
	}

	// Check for hosts parameter
	std::string hosts = arg_conf_inst->GetHosts();

	// Check for hosts parameter
	std::string ports = arg_conf_inst->GetPorts();
	
	//Execute scan
	if (hosts.length() != 0 && ports.length() != 0) {
		std::vector<std::string> host_vect = translate_hosts(hosts);
		std::vector<std::string> port_vect = translate_ports(ports);

		//Only scan if there are ports to scan
		if(host_vect.size() > 0 && port_vect.size() > 0)
			start_scan(arg_conf_inst, host_vect, port_vect);
	}
	else {

		std::string username = arg_conf_inst->GetUsr();
		if (username.length() != 0) {

			std::unordered_map<std::string, UserInfo*> tmp_user_info_map;
			
			//Get all groups
			std::string domain = arg_conf_inst->GetDomain();
			get_user_groups_all(username, domain, &tmp_user_info_map);

			for (std::unordered_map<std::string, UserInfo*>::iterator user_info_it = tmp_user_info_map.begin();
				user_info_it != tmp_user_info_map.end(); ++user_info_it) {

				std::string cur_user = user_info_it->first;
				DebugFprintf(outlogfile, PRINT_INFO1, "%s,", cur_user.c_str());

				UserInfo *user_info = user_info_it->second;

				//Get user information
				if (get_user_info(username, user_info)) {
					DebugFprintf(outlogfile, PRINT_INFO1, "%s,", user_info->GetFlags().c_str());
					DebugFprintf(outlogfile, PRINT_INFO1, "%s,", user_info->GetPasswordAge().c_str());
				}

				std::vector<std::string> group_list = user_info->GetGroups();
				if (group_list.size() > 0) {
					DebugFprintf(outlogfile, PRINT_INFO1, "\"");
					for (std::vector<std::string>::iterator grp_it = group_list.begin(); grp_it != group_list.end(); ++grp_it) {
						std::string cur_group = *grp_it;
						DebugFprintf(outlogfile, PRINT_INFO1, "%s,", cur_group.c_str());
					}
					DebugFprintf(outlogfile, PRINT_INFO1, "\"");
				}
				DebugFprintf(outlogfile, PRINT_INFO1, "\n");
			}

			//TODO free memory
		}

		// Check for processes parameter
		if( arg_conf_inst->ListProcesses()) {
			//Enable debug priv
			enable_token_priv(NULL, SE_DEBUG_NAME);

			std::unordered_map<size_t, ProcessInfo*> pid_process_info_map;
			get_processes(&pid_process_info_map);

			get_network_info(&pid_process_info_map);

			print_process_data(pid_process_info_map);
		}

		// Get the command if no host was specified
		std::string cmd = arg_conf_inst->GetCommand();
		if ( cmd.length() > 0 ) {
			CreateProcessWithPipeComm(cmd);
		}

		// Check for processes parameter
		if (arg_conf_inst->EnumerateLocal()) {
			print_ip_config();
			print_env();
		}
	}
}

ArgConfig* parse_args(size_t argc, char **argv) {

	int c;
	std::string input_ports;
	ArgConfig *arg_conf_inst = new ArgConfig();

	while ((c = getopt(argc, argv, "f:b:d:c:g:o:P:v:s:l:p:t:u:hxyraneizEI")) != -1) {

		switch (c)
		{
		case 'p':
			if (input_ports.length() > 0)
				input_ports.append(",");
			input_ports.append(optarg);
			break;
		case 'b':
			if (optarg) {
				std::string execution_type = optarg;
				std::transform(execution_type.begin(), execution_type.end(), execution_type.begin(), ::tolower);
				if (execution_type.compare(WINRM_EXEC) != 0 && execution_type.compare(SMB_EXEC) != 0 && execution_type.compare(WMI_EXEC) != 0) {
					DbgFprintf(outlogfile, PRINT_ERROR, "[-] Invalid execution type parameter.\n");
					break;
				}
				arg_conf_inst->SetExecutionType(execution_type);
			}
			break;
		case 't':
			if (optarg) {
				global_timeout = atoi(optarg);
				global_timeout_micro = 0;
			}
		case 'v':
			if (optarg)
				verbosity += atoi(optarg);
			break;
		case 'f':
			if (optarg)
				arg_conf_inst->SetLocalExecutablePath(optarg);
			break;
		case 'c':
			if (optarg)
				arg_conf_inst->SetCommand(optarg);
			break;
		case 'u':
			if (optarg)
				arg_conf_inst->SetUsr(optarg);
			break;
		case 'd':
			if (optarg)
				arg_conf_inst->SetDomain(optarg);
			break;
		case 'l':
			if (optarg)
				arg_conf_inst->SetLogPath(optarg);
			break;
		case 'g':
			if (optarg)
				arg_conf_inst->SetADGroup(optarg);
			break;
		case 's':
			if (optarg)
				arg_conf_inst->SetHosts(optarg);
			break;
		case 'P':
			if (optarg)
				arg_conf_inst->SetPw(optarg);
			break;
		case 'o':
			if (optarg)
				arg_conf_inst->SetOldPw(optarg);
			break;
		case 'y':
			arg_conf_inst->SetListProcessesFlag(true);
			break;
		case 'E':
			arg_conf_inst->SetEnumerateFlag(true);
			break;
		case 'e':
			arg_conf_inst->SetWebEnumFlag(true);
			break;
		case 'x':
			arg_conf_inst->SetListRemoteSessionsFlag(true);
			break;
		case 'z':
			arg_conf_inst->SetListServerInfoFlag(true);
			break;
		case 'r':
			arg_conf_inst->SetListRemoteSharesFlag(true);
			break;
		case 'n':
			arg_conf_inst->SetChangePwFlag(true);
			break;
		case 'a':
			arg_conf_inst->SetPwSprayFlag(true);
			break;
		case 'i':
			arg_conf_inst->SetListRemoteNetstatFlag(true);
			break;
		case 'I':
			arg_conf_inst->SetListWmiProcessesFlag(true);
			break;
		case 'h':
			usage();
			break;
		case '?':
		default:
			DbgFprintf(outlogfile, PRINT_WARN, "[-] Unknown option %c\n", c);
		}
	}

	//Reset values
	optind = 0;

	//Add ports to list based on defined settings
	//SMB
	if (arg_conf_inst->WebEnum() || arg_conf_inst->ListRemoteSessions() || arg_conf_inst->ListServerInfo()
		|| arg_conf_inst->ListRemoteShares() || arg_conf_inst->ChangePw() 
		|| !arg_conf_inst->GetExecutionType().compare(SMB_EXEC)) {

		if (input_ports.length() > 0)
			input_ports.append(",");
		input_ports.append(SMB_PORT_STR);
	}
	//WMI
	if (arg_conf_inst->ListRemoteNetstat()) {

		if (input_ports.length() > 0)
			input_ports.append(",");
		input_ports.append(WMI_PORT_STR);
	}
	//WINRM
	if (!arg_conf_inst->GetExecutionType().compare(WINRM_EXEC)) {

		if (input_ports.length() > 0)
			input_ports.append(",");
		input_ports.append(WSMAN_PORT_STR);
	}

	//Add ports entry
	if (input_ports.length() > 0) 
		arg_conf_inst->SetPorts(input_ports);
	

	return arg_conf_inst;
}

std::string get_next_arg(std::string line, std::string *next_arg) {

	std::string ret_str = "";
	size_t next_offset = 0;
	size_t first_space = line.find_first_of(" ");
	size_t first_quote = line.find_first_of("\"");
	if ( first_quote != std::string::npos && ((first_space == std::string::npos) ||
		                                      (first_quote < first_space ) )) {

		size_t second_quote = line.find("\"", first_quote+1);
		if (second_quote != std::string::npos) {
			*next_arg = line.substr(first_quote+1, second_quote - first_quote - 1);
			next_offset = second_quote - first_quote + 2;
			if (next_offset < line.length())
				ret_str = line.substr(next_offset, std::string::npos);

		}
		else {
			*next_arg = line.substr(0, first_space);
			next_offset = first_space + 1;
			if (next_offset < line.length())
				ret_str = line.substr(next_offset, std::string::npos);
		}
	}
	else if(first_space != std::string::npos)
	{
		*next_arg = line.substr(0, first_space);
		next_offset = first_space + 1;
		if (next_offset < line.length())
			ret_str = line.substr(next_offset, std::string::npos);
	}
	else 
		*next_arg = line.substr(0, std::string::npos);
	

	return ret_str;

}

void convert_line_to_argv(std::string line, size_t *line_argc, char ***line_argv) {

	std::vector<char*> argv;
	DWORD i;
	std::string next_arg;
	std::string remaining_str = line;
		
	while (remaining_str.length() > 0) {

		//Get the next arg
		remaining_str = get_next_arg(remaining_str, &next_arg);

		//Allocate new char string
		char * next_str = (char *)calloc(1, next_arg.length() + 1);
		if (next_str == NULL) {
			DbgFprintf(outlogfile, PRINT_WARN, "[-] Buffer allocation failed. Error: %d\n", GetLastError());
			return;
		}
		memcpy(next_str, next_arg.c_str(), next_arg.length());
		next_arg.assign("");

		//Add to vector
		argv.push_back(next_str);

	}
	
	//Current number of arguments
	*line_argc = argv.size() + 1;
	*line_argv = (char **)calloc(1, sizeof(char *) * argv.size() + 1);
	if (*line_argv == NULL) {
		DbgFprintf(outlogfile, PRINT_ERROR, "[-] calloc returned NULL\n");
		exit(1);
	}

	std::vector<char*>::iterator it;
	for (it = argv.begin(), i = 1; it != argv.end(); it++, i++) {
		char **argv_ptr = *(line_argv);
		if ( argv_ptr == NULL)
			break;
		argv_ptr[i] = *it;
	}		

	return;
}

int main(int argc, char **argv)
{		
	std::string line;
	size_t line_argc = 0;
	char **line_argv = NULL;

	//DebugFprintf(outlogfile, PRINT_ERROR, "[*] Arg Count: %d\n", argc);
	//for (int i = 0; i < argc; i++) {
	//	DebugFprintf(outlogfile, PRINT_ERROR, "[*] Arg: %s\n", argv[i]);
	//}
	
	if (argc > 1) {
		ArgConfig* arg_conf_inst = parse_args(argc, argv);
		process_args(arg_conf_inst);
	}
	else {

		//Create kill thread, must be dynamically allocated or kill function will crash
		KillThread *kt = new KillThread(KILL_THREAD_TIMEOUT);

		//Print usage
		usage();
		printf("Type \"exit\" to end session.\n");
		printf("> ");
		while (std::getline(std::cin, line) && line.compare("exit") != 0 && line.compare("quit") != 0) {
						
			//Set kill flag to false
			kt->set_kill_flag(false);
			
			//Convert line to argc, argv
			convert_line_to_argv(line, &line_argc, &line_argv);

			ArgConfig* arg_conf_inst = parse_args(line_argc, line_argv);
			//if(args_map.size() > 0)
			process_args(arg_conf_inst);

			printf("\n> ");

			//Create new kill timer
			kt = new KillThread(KILL_THREAD_TIMEOUT);
		}

		printf("Exiting.\n");
	}

	return 0;
}


#ifdef _DLL_ENTRY


extern "C" __declspec (dllexport) void __cdecl RegisterDll(char *args) {
	//FILE* fd;
    //fopen_s(&fd, "C:\\Users\\Public\\o.txt", "a+");
    //fprintf(fd, "%s", args);
	//fclose(fd);	
}

#endif

#ifdef _DLL_ENTRY

/*
 * Current DLL hmodule.
 */
static HMODULE dll_handle = NULL;

//===============================================================================================//
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
	BOOL bReturnValue = TRUE;
	DWORD dwResult = 0;
	unsigned int ret = 0;

	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
		dll_handle = (HMODULE)hinstDLL;
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return bReturnValue;
}
#endif