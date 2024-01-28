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