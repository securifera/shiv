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
