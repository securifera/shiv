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