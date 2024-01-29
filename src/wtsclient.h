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

class WTSClient {
public:

	virtual ~WTSClient() {}
	WTSClient(unsigned int id);

	void SetProtocol(unsigned short client_proto) { this->protocol = client_proto; }
	void SetState(unsigned short client_state) { this->state = client_state; }
	void SetSessionName(std::string session_name) { this->session_name = session_name; }
	void SetDomain(std::string domain){ this->domain = domain; }
	void SetUsername(std::string user){ this->username = user; }
	void SetClientAddress(std::string client_addr){ this->client_addr = client_addr; }

	std::string GetSessionName(){ return this->session_name; }
	std::string GetDomain(){ return this->domain; }
	std::string GetUsername(){ return this->username; }
	std::string GetClientAddress(){ return this->client_addr; }
	std::string GetFQDN();
	std::string GetProtocol();
	std::string GetState();
	std::string toString();
	

protected:
private:

	unsigned int id;
	short protocol;
	short state;
	std::string session_name;
	std::string domain;
	std::string username;
	std::string client_addr;

	
};

BOOL get_sessions(std::string comp, std::vector<WTSClient*>* wtsclient_list);