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
#include "user_info.h"

static const short FILEINFO_FILE = 0;
static const short FILEINFO_DIRECTORY = 1;

class FileInfo {
public:

	virtual ~FileInfo() {}
	FileInfo(std::string name) { this->name = name; this->file_size = { 0 }; }
	void SetSize(LARGE_INTEGER size) { this->file_size = size; }
	void SetType(short type) { this->file_type = type; }

	std::string GetFilename() { return this->name; };
	DWORD GetFileType() { return this->file_type; };
	LARGE_INTEGER GetSize() { return this->file_size; };

protected:
private:
	std::string name;
	short file_type;
	LARGE_INTEGER file_size;
};

BOOL get_active_users(std::vector<std::string> *user_list);
std::string get_username();
std::wstring get_computer_name();
void print_ip_config();
void print_env();
BOOL check_pw(std::string username, std::string domain, std::string password);
BOOL get_user_groups(std::string username, std::wstring wdomain, UserInfo* user_info);
BOOL get_user_info(std::string username, UserInfo *user_info);
BOOL get_users_in_group(std::string group, std::wstring wdomain, std::vector<std::string>* user_list);
BOOL get_users_in_localgroup(std::string group, std::wstring wdomain, std::vector<std::string>* user_list);
BOOL get_user_localgroups(std::string username, std::wstring wdomain, UserInfo* user_info);
BOOL get_user_groups_all(std::string username, std::string domain, std::unordered_map<std::string, UserInfo*> *user_info_map);
BOOL get_users_in_group_all(std::string group, std::string domain, std::unordered_map<std::string, std::vector<std::string>*>* group_user_list_map);

BOOL check_write_access(std::string file_path);
BOOL list_files(std::string file_path, std::vector<FileInfo*>* file_list);
BOOL remotely_change_user_pw(std::string remote_host, std::string username, std::string old_password, std::string new_password);
BOOL enumerate_web_endpoints(std::string srv_str);
BOOL get_domain_controller(wchar_t** domain_str);
DWORD enable_token_priv(HANDLE token, char* priv);

BOOL convert_file_to_shellcode(std::string file_path, std::string file_args, std::vector<unsigned char>** sc_bytes);

std::wstring s2ws(const std::string& str);
std::string ws2s(const std::wstring& wstr);