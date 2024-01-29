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