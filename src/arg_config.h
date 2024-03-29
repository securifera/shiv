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

#pragma once

#include <string>


class ArgConfig {
public:

	//String settings
	std::string GetHosts() { return hosts; };
	void SetHosts(std::string str_arg) { hosts = str_arg; };

	std::string GetPorts() { return ports; };
	void SetPorts(std::string str_arg) { ports = str_arg; };

	std::string GetExecutionType() { return execution_type; };
	void SetExecutionType(std::string str_arg) { execution_type = str_arg; };

	std::string GetLocalExecutablePath() { return local_executable_path; };
	void SetLocalExecutablePath(std::string str_arg) { local_executable_path = str_arg; };

	std::string GetCommand() { return command; };
	void SetCommand(std::string str_arg) { command = str_arg; };

	std::string GetUsr() { return username; };
	void SetUsr(std::string str_arg) { username = str_arg; };

	std::string GetPw() { return pw; };
	void SetPw(std::string str_arg) { pw = str_arg; };

	std::string GetOldPw() { return old_pw; };
	void SetOldPw(std::string str_arg) { pw = str_arg; };

	std::string GetDomain() { return domain; };
	void SetDomain(std::string str_arg) { domain = str_arg; };

	std::string GetLogPath() { return log_path; };
	void SetLogPath(std::string str_arg) { log_path = str_arg; };

	std::string GetADGroup() { return ad_group; };
	void SetADGroup(std::string str_arg) { ad_group = str_arg; };


	//Boolean settings
	bool ListProcesses() { return list_process_info_flag; };
	void SetListProcessesFlag(bool val) { list_process_info_flag = val; };

	void SetEnumerateFlag(bool val) { enumerate_local_flag = val; };
	bool EnumerateLocal() { return enumerate_local_flag; };

	bool ListRemoteSessions() { return list_remote_sessions_flag; };
	void SetListRemoteSessionsFlag(bool val) { list_remote_sessions_flag = val; };

	bool ListServerInfo() { return list_server_info_flag; };
	void SetListServerInfoFlag(bool val) { list_server_info_flag = val; };

	bool ListRemoteShares() { return list_remote_shares_flag; };
	void SetListRemoteSharesFlag(bool val) { list_remote_shares_flag = val; };

	bool ListRemoteNetstat() { return list_remote_netstat_flag; };
	void SetListRemoteNetstatFlag(bool val) { list_remote_netstat_flag = val; };

	bool ListWmiProcesses() { return list_wmi_process_flag; }
	void SetListWmiProcessesFlag(bool val) { list_wmi_process_flag = val; }

	bool PwSpray() { return pw_spray_flag; };
	void SetPwSprayFlag(bool val) { pw_spray_flag = val; };

	bool WebEnum() { return web_enum_flag; };
	void SetWebEnumFlag(bool val) { web_enum_flag = val; };

	bool ChangePw() { return change_pw_flag; };
	void SetChangePwFlag(bool val) { change_pw_flag = val; };


protected:


private:

	std::string hosts;
	std::string ports;

	std::string username;
	std::string pw;
	std::string old_pw;
	std::string domain;
	std::string command;
	std::string execution_type;
	std::string local_executable_path;

	std::string log_path;

	std::string ad_group;

	bool list_process_info_flag = false;
	bool list_server_info_flag = false;
	bool list_remote_sessions_flag = false;
	bool list_remote_shares_flag = false;
	bool list_remote_netstat_flag = false;
	bool enumerate_local_flag = false;
	bool list_wmi_process_flag = false;
	bool pw_spray_flag = false;
	bool web_enum_flag = false;
	bool change_pw_flag = false;
};