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
#include <ctime>

#include "debug.h"
#include "user_info.h"
#include "utils.h"


std::string UserInfo::GetFlags() {
	std::string ret_str;
	ret_str.append("\"");
	if (this->PasswordExpired())
		ret_str.append("UF_PASSWORD_EXPIRED,");

	if (this->NoDelegatedAccess())
		ret_str.append("UF_NOT_DELEGATED,");

	if (this->Disabled())
		ret_str.append("UF_ACCOUNTDISABLE,");

	if (this->Locked())
		ret_str.append("UF_LOCKED,");

	if (this->SmartCardRequired())
		ret_str.append("UF_SMARTCARD_REQUIRED,");

	ret_str.append("\"");

	return ret_str;
}

std::string UserInfo::GetPasswordAge() {
	std::string ret_str;
	char time_buf[100];
	memset(time_buf, 0, 100);

	ret_str.append("Password last set: ");
	unsigned int pw_age = this->password_age;

	time_t t = time(0);
	struct tm p;

	// Subtract pw age
	t = t - pw_age;

	// convert now to string form
	localtime_s(&p, &t);
	strftime(time_buf, 100, "%m%d%Y-%H:%M:%S", &p);
	ret_str.append(time_buf);

	return ret_str;
}

void print_session_data(std::unordered_map<std::string, UserInfo *> user_info_map, std::string domain) {

	//Get groups for each user
	std::wstring wdomain(domain.begin(), domain.end());
	if (user_info_map.size() > 0) {

		DebugFprintf(outlogfile, PRINT_INFO1, "\nUser,Hosts,Groups,User Flags,Source IP,Script Path\n");
		for (std::unordered_map<std::string, UserInfo *>::iterator user_info_it = user_info_map.begin();
			user_info_it != user_info_map.end(); ++user_info_it) {

			std::string cur_user = user_info_it->first;
			//Print user
			DebugFprintf(outlogfile, PRINT_INFO1, "%s,", cur_user.c_str());

			//Get user data
			UserInfo *cur_user_data = user_info_it->second;

			//Print computers
			std::vector<std::string> cur_hosts = cur_user_data->GetActiveSessions();
			DebugFprintf(outlogfile, PRINT_INFO1, "\"");
			for (std::vector<std::string>::iterator hosts_it = cur_hosts.begin(); hosts_it != cur_hosts.end(); ++hosts_it) {
				std::string cur_host = *hosts_it;
				DebugFprintf(outlogfile, PRINT_INFO1, "%s,", cur_host.c_str());
			}
			DebugFprintf(outlogfile, PRINT_INFO1, "\",");

			//Print groups
			if (get_user_groups(cur_user, wdomain, cur_user_data)) {

				std::vector<std::string> group_list = cur_user_data->GetGroups();
				if (group_list.size() > 0) {
					DebugFprintf(outlogfile, PRINT_INFO1, "\"");
					for (std::vector<std::string>::iterator grp_it = group_list.begin(); grp_it != group_list.end(); ++grp_it) {
						std::string cur_group = *grp_it;
						DebugFprintf(outlogfile, PRINT_INFO1, "%s,", cur_group.c_str());
					}
					DebugFprintf(outlogfile, PRINT_INFO1, "\"");
				}
			}
			DebugFprintf(outlogfile, PRINT_INFO1, ",");

			//Print user information
			if (get_user_info(cur_user, cur_user_data)) {
				DebugFprintf(outlogfile, PRINT_INFO1, cur_user_data->GetFlags().c_str());
			}
			DebugFprintf(outlogfile, PRINT_INFO1, ",");

			//Print client address
			DebugFprintf(outlogfile, PRINT_INFO1, "%s,", cur_user_data->GetClientAddress().c_str());


			//Print script path
			DebugFprintf(outlogfile, PRINT_INFO1, cur_user_data->GetScriptPath().c_str());
			DebugFprintf(outlogfile, PRINT_INFO1, "\n");
		}
		DebugFprintf(outlogfile, PRINT_INFO1, "\n");
	}
}