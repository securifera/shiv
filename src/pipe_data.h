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

#define CMD_TYPE 101
#define STD_IN_TYPE 102
#define STD_OUT_TYPE 103
#define SHELL_CODE_TYPE 104

class PipeData {
public:

	PipeData::PipeData() { data_type = 0; data_len	= 0; };
	uint16_t GetType() { return data_type; };
	void SetType(uint16_t type_val) { data_type = type_val; };

	std::vector<unsigned char> GetData() { return data; };
	void SetData(std::vector<unsigned char> data_param) { data = data_param; };

	bool PipeData::Populate(char* readBuf, uint32_t dwRead);
	std::vector<unsigned char>* ToBytes();

protected:
private:

	uint16_t data_type;
	uint32_t data_len;
	std::vector<unsigned char> data;
	std::vector<unsigned char> tmp_data;

};

class CmdData : public PipeData {
public:

	CmdData();
	CmdData(std::string cmd);

protected:
private:

};

class StdInData : public PipeData {
public:

	StdInData();
	StdInData(std::string cmd);

protected:
private:

};

class ScData : public PipeData {
public:

	ScData();
	ScData(std::vector<unsigned char> *sc);

protected:
private:

};