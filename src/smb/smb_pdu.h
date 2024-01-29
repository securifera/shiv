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

#define IOV_OFFSET_NEG (rep->security_buffer_offset - SMB_HEADER_SIZE - (SMB2_NEGOTIATE_REPLY_SIZE & 0xfffe))
#define IOV_OFFSET_SESS (rep->security_buffer_offset - SMB_HEADER_SIZE - (SMB_SESSION_SETUP_REPLY_SIZE & 0xfffe))

struct smb_pdu {

    struct smb_header header;
    resp_handler_func resp_handler;

    uint8_t hdr[SMB_HEADER_SIZE];
    void* pdu_data;

    struct pdu_buffer_array send_buf_array;
    struct pdu_buffer_array recv_buf_array;

};

struct pdu_buffer* add_pdu_buffer(struct pdu_buffer_array* v, uint8_t* buf, int len, void (*free)(void*));
int get_static_pdu_size(struct smb_context* smb_context_inst, struct smb_pdu* pdu);
void queue_pdu(struct smb_context* smb_context_inst, struct smb_pdu* pdu);
struct smb_pdu* allocate_pdu(uint64_t session_id, uint8_t command, resp_handler_func resp_handler);
void free_pdu(struct smb_pdu* pdu);
void free_pdu_buffer(struct pdu_buffer_array* pdu_buf_arr);

int process_static_pdu(struct smb_context* smb_context_inst, struct smb_pdu* pdu);
int process_dynamic_pdu(struct smb_context* smb_context_inst, struct smb_pdu* pdu);

void encode_smb_header(struct smb_context* smb_context_inst, struct pdu_buffer* pdu_array, struct smb_header* hdr);
int decode_smb_header(struct pdu_buffer* pdu_array, struct smb_header* hdr);
