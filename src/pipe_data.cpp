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

#include "pipe_data.h"
#include "debug.h"

std::vector<unsigned char>* PipeData::ToBytes() {

    std::vector<unsigned char>* pipe_data_bytes = new std::vector<unsigned char>();

    //Add the data type - 2 bytes
    pipe_data_bytes->insert(pipe_data_bytes->end(), (char)((data_type & 0xff00) >> 8));
    pipe_data_bytes->insert(pipe_data_bytes->end(), (char)(data_type & 0xff));

    //Add the data length - 4 bytes
    uint32_t data_len = (uint32_t)this->data.size();
    pipe_data_bytes->insert(pipe_data_bytes->end(), (char)((data_len & 0xff000000) >> 24));
    pipe_data_bytes->insert(pipe_data_bytes->end(), (char)((data_len & 0xff0000) >> 16));
    pipe_data_bytes->insert(pipe_data_bytes->end(), (char)((data_len & 0xff00) >> 8));
    pipe_data_bytes->insert(pipe_data_bytes->end(), (char)(data_len & 0xff));

    //Add data
    pipe_data_bytes->insert(pipe_data_bytes->end(), this->data.begin(), this->data.end());

    return pipe_data_bytes;
}

bool PipeData::Populate(char* readBuf, uint32_t dwRead) {

    //DebugFprintf(outlogfile, PRINT_ERROR, "[+] Populating the object.\n");
    //Insert the data
    tmp_data.insert(tmp_data.end(), readBuf, readBuf + dwRead);

    //Check if we are mid message
    if (data_type == 0 && tmp_data.size() >= 2) {
        //Set message type
        data_type = (tmp_data.at(0) << 8) + tmp_data.at(1);
        //Remove data from temp byte vector
        tmp_data.erase(tmp_data.begin(), tmp_data.begin() + 2);
    }

    if (data_len == 0 && tmp_data.size() >= 4) {
        //Set message length
        data_len = (tmp_data.at(0) << 24) + (tmp_data.at(1) << 16) + (tmp_data.at(2) << 8) + tmp_data.at(3);
        //Remove data from temp byte vector
        tmp_data.erase(tmp_data.begin(), tmp_data.begin() + 4);

        //DebugFprintf(outlogfile, PRINT_INFO1, "\t[*] Data Length %d bytes.\n", data_len);
    }

    if (data.size() == 0 && data_len != 0 &&  tmp_data.size() >= data_len) {
        //Set the data
        data.insert(data.end(), tmp_data.begin(), tmp_data.begin() + data_len);       
        //Remove data from temp byte vector
        tmp_data.erase(tmp_data.begin(), tmp_data.begin() + data_len);

        //Return true to signal the data is ready to be handled
        return true;
    }

    return false;
}

CmdData::CmdData() {
    this->SetType((uint16_t)CMD_TYPE);
}

CmdData::CmdData(std::string cmd) : CmdData() {
    std::vector<unsigned char> data = this->GetData();
    data.insert(data.end(), cmd.begin(), cmd.end());
    this->SetData(data);
}

StdInData::StdInData() {
    this->SetType((uint16_t)STD_IN_TYPE);
}

StdInData::StdInData(std::string cmd) : StdInData() {
    std::vector<unsigned char> data = this->GetData();
    data.insert(data.end(), cmd.begin(), cmd.end());
    this->SetData(data);
}

ScData::ScData() {
    this->SetType((uint16_t)SHELL_CODE_TYPE);
}

ScData::ScData(std::vector<unsigned char>* sc) : ScData() {
    std::vector<unsigned char> data = this->GetData();
    data.insert(data.end(), sc->begin(), sc->end());
    this->SetData(data);
}