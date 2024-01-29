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

#include <stdint.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>

enum class SMB_RECV_STATE : int {
    SMB2_RECV_SPL = 0,
    SMB2_RECV_HEADER,
    SMB2_RECV_STATIC,
    SMB2_RECV_DYNAMIC,
    SMB2_RECV_PAD,
    SMB2_RECV_TRFM,
};

struct socket_buffer
{
    unsigned long buffer_len;
    void *buffer;        
};

int send_wrap(SOCKET sock, struct socket_buffer* sock_buffer, int arr_size);
int recv_wrap(SOCKET sock, struct socket_buffer* sock_buffer, int arr_size);
int close_wrap(SOCKET sock);
int connect_wrap(const struct addrinfo* ai, int* fd_out);
int connect_to_server(struct smb_context* smb_context_inst, std::string server);
int connect_wrap_loop(const struct addrinfo* addr_info_inst);
int send_recv(struct smb_context* smb_context_inst, struct smb_pdu* pdu);


