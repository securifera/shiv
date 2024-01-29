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
#include <vector>
#include <lmaccess.h>
#include <unordered_map>

class UserInfo {
public:

	virtual ~UserInfo() {}
	UserInfo(std::string name) { this->name = name; }

	void SetUserFlags(unsigned int user_flags) { this->user_flags = user_flags; }
	void SetPasswordAge(unsigned int password_age) { this->password_age = password_age; }
	void SetScriptPath(std::string script_path) { this->script_path = script_path; }
	void SetClientAddress(std::string client_addr) { this->client_addr = client_addr; }
		
	bool SmartCardRequired() { return (user_flags & UF_SMARTCARD_REQUIRED) > 0; };
	bool NoDelegatedAccess() { return (user_flags & UF_NOT_DELEGATED) > 0; };
	bool Disabled() { return (user_flags & UF_ACCOUNTDISABLE) > 0; };
	bool Locked() { return (user_flags & UF_LOCKOUT); };
	bool PasswordExpired() { return (user_flags & UF_PASSWORD_EXPIRED);};

	std::string GetUsername() { return this->name; };
	std::string GetClientAddress() { return this->client_addr; };
	std::string GetScriptPath() { return this->script_path; };	
	std::string GetFlags();
	std::string UserInfo::GetPasswordAge();
	std::vector<std::string> GetGroups() { return this->groups; };
	std::vector<std::string> GetActiveSessions() { return this->sessions; };

	void AddSession(std::string host) { sessions.push_back(host); }
	void AddGroup(std::string group) { groups.push_back(group); }

protected:
private:

	unsigned int user_flags;
	unsigned int password_age;
	std::string name;
	std::string client_addr;
	std::string script_path;
	std::vector<std::string> groups;
	std::vector<std::string> sessions;

};

//Static functions
void print_session_data(std::unordered_map<std::string, UserInfo *> user_info_map, std::string domain);
