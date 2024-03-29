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

#include <tlhelp32.h>
#include <unordered_map>

#define PROCESS_ARCH_UNKNOWN	0
#define PROCESS_ARCH_X86		1
#define PROCESS_ARCH_X64		2
#define PROCESS_ARCH_IA64		3

class ProcessInfo {
public:

	virtual ~ProcessInfo() {}
	ProcessInfo(size_t pid) { this->pid = pid;  ppid = 0;  process_arch = 0; session_id = 0; }

	void SetPid(size_t pid) { this->pid = pid; }
	void SetParentPid(size_t ppid) { this->ppid = ppid; }
	void SetSessionId(unsigned int session_id) { this->session_id = session_id; }
	void SetUsername(std::string process_user) { this->process_user = process_user; }
	void SetExeName(std::string exe_name) { this->exe_name = exe_name; }
	void SetExePath(std::string exe_path) { this->exe_path = exe_path; }
	void SetArch(unsigned short arch) { this->process_arch = arch; }
	void SetServiceName(std::string svc_name ) { this->svc_name = svc_name; }

	size_t GetPid() { return this->pid; };
	size_t GetParentPid() { return this->ppid; };
	unsigned int GetSessionId() { return this->session_id; };
	std::string GetUsername() { return this->process_user; };
	std::string GetExeName() { return this->exe_name; };
	std::string GetExePath() { return this->exe_path; };
	std::string GetServiceName() { return this->svc_name; };
	std::string ProcessInfo::GetArch();
	std::vector<std::string> GetOpenPorts() { return this->open_ports; };
	std::vector<std::string> GetConnections() { return this->connections; };

	void AddOpenPort(std::string host) { open_ports.push_back(host); }
	void AddConnection(std::string group) { connections.push_back(group); }
	
protected:
private:

	size_t pid;
	size_t ppid;
	std::string exe_name;
	std::string exe_path;
	std::string process_user;
	std::string svc_name;
	unsigned short process_arch;
	unsigned int session_id;
	std::vector<std::string> open_ports;
	std::vector<std::string> connections;

};

// static functions
BOOL get_processes(std::unordered_map<size_t, ProcessInfo *> *pid_process_info_map);
void print_process_data(std::unordered_map<size_t, ProcessInfo *> process_info_map);
