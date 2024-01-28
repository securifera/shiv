#pragma once

#include <thread>
#include <atomic>
#include "arg_config.h"

// Ensure this object is only created with "new" or suicide in kill_func will crash program
class KillThread {
public:

	KillThread(unsigned int timeout_s) {
		this->timeout_s = timeout_s;
		run();
	}
	   
	void set_kill_flag(bool flag_val) {
		this->kill_flag = flag_val;
	}	
	
private:

	void run() {
		std::thread t1(&KillThread::kill_func, this);
		t1.detach();
	}

	void kill_func()
	{
		std::this_thread::sleep_for(std::chrono::seconds(this->timeout_s));
		if (kill_flag)
			std::terminate();
		else
			delete this;
	}

	std::atomic<bool> kill_flag = true;
	unsigned int timeout_s = 0;
};


void start_scan(ArgConfig* arg_conf_inst, std::vector<std::string> hosts, std::vector<std::string> ports);
void port_scan(ArgConfig* arg_conf_inst, std::string host, std::vector<std::string> ports);