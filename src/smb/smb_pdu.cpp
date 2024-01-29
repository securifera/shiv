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

#include <stdio.h>
#include "smb.h"
#include "smb_pdu.h"
#include "smb_socket.h"
#include "smb_utils.h"
#include "..\debug.h"

int process_static_session_setup_pdu(struct smb_context* smb_context_inst, struct smb_pdu* pdu)
{
    struct session_setup_reply_msg* rep;
    struct pdu_buffer* pdu_array = &smb_context_inst->recv_buf_array.pdu_array[smb_context_inst->recv_buf_array.pdu_array_size - 1];
    uint16_t struct_size;

    rep = (session_setup_reply_msg *)malloc(sizeof(*rep));
    if (rep == NULL) {
        DbgFprintf(outlogfile, PRINT_ERROR, "SMB Failed allocating buffer.");
        return -1;
    }
    pdu->pdu_data = rep;

    buf_get_uint16(pdu_array, 0, &struct_size);
    if (struct_size != SMB_SESSION_SETUP_REPLY_SIZE ||
        (struct_size & 0xfffe) != pdu_array->len) {
        DbgFprintf(outlogfile, PRINT_ERROR, "[-] SMB Incorrect session setup reply length");
        return -1;
    }

    buf_get_uint16(pdu_array, 2, &rep->session_flags);
    buf_get_uint16(pdu_array, 4, &rep->security_buffer_offset);
    buf_get_uint16(pdu_array, 6, &rep->security_buffer_length);

    //Set session id
    smb_context_inst->session_id = smb_context_inst->hdr.session_id;

    if (rep->security_buffer_length == 0)
        return 0;
    
    if (rep->security_buffer_offset < SMB_HEADER_SIZE + (SMB_SESSION_SETUP_REPLY_SIZE & 0xfffe)) {
        DbgFprintf(outlogfile, PRINT_ERROR, "[-] SMB Incorrect security buffer length");
        return -1;
    }

    return IOV_OFFSET_SESS + rep->security_buffer_length;
}


int process_static_negotiate_pdu(struct smb_context* smb_context_inst, struct smb_pdu* pdu)
{
    struct pdu_buffer* pdu_array = &smb_context_inst->recv_buf_array.pdu_array[smb_context_inst->recv_buf_array.pdu_array_size - 1];
    uint16_t struct_size;

    struct negotiate_reply_msg* rep = (negotiate_reply_msg*)malloc(sizeof(*rep));
    if (rep == NULL) {
        DbgFprintf(outlogfile, PRINT_ERROR, "SMB Failed allocating buffer.");
        return -1;
    }
    pdu->pdu_data = rep;

    buf_get_uint16(pdu_array, 0, &struct_size);
    if (struct_size != SMB2_NEGOTIATE_REPLY_SIZE || (struct_size & 0xfffe) != pdu_array->len) {
        DbgFprintf(outlogfile, PRINT_ERROR, "[-] SMB Incorrect negotiate reply length");
        return -1;
    }

    buf_get_uint16(pdu_array, 2, &rep->security_mode);
    buf_get_uint16(pdu_array, 4, &rep->dialect_revision);
    memcpy(rep->server_guid, pdu_array->buf + 8, 16);
    buf_get_uint32(pdu_array, 24, &rep->capabilities);
    buf_get_uint32(pdu_array, 28, &rep->max_transact_size);
    buf_get_uint32(pdu_array, 32, &rep->max_read_size);
    buf_get_uint32(pdu_array, 36, &rep->max_write_size);
    buf_get_uint64(pdu_array, 40, &rep->system_time);
    buf_get_uint64(pdu_array, 48, &rep->server_start_time);
    buf_get_uint16(pdu_array, 56, &rep->security_buffer_offset);
    buf_get_uint16(pdu_array, 58, &rep->security_buffer_length);

    buf_get_uint16(pdu_array, 6, &rep->negotiate_context_count);
    buf_get_uint32(pdu_array, 60, &rep->negotiate_context_offset);

    if (rep->security_buffer_length == 0)
        return 0;
    
    if (rep->security_buffer_offset < SMB_HEADER_SIZE + (SMB2_NEGOTIATE_REPLY_SIZE & 0xfffe)) {
        DbgFprintf(outlogfile, PRINT_ERROR, "[-] SMB Incorrect security buffer length");
        return -1;
    }

    if (rep->dialect_revision >= SMB2_VERSION_0311)
        return smb_context_inst->static_pdu_len - SMB_HEADER_SIZE - (SMB2_NEGOTIATE_REPLY_SIZE & 0xfffe);
    else
        return IOV_OFFSET_NEG + rep->security_buffer_length;
    
}

int parse_negotiate_contexts(struct negotiate_reply_msg* rep, struct pdu_buffer* pdu_array, int offset, int count)
{
    uint16_t type, len;

    while (count--) {
        buf_get_uint16(pdu_array, offset, &type);
        offset += 2;
        buf_get_uint16(pdu_array, offset, &len);
        offset += 6;

        switch (type) {
            case SMB2_PREAUTH_INTEGRITY_CAP:
                break;
            case SMB2_ENCRYPTION_CAP:       
                break;
            default:
                DbgFprintf(outlogfile, PRINT_ERROR, "[-] SMB Unknown negotiate context type %d", type);
                return -1;
        }
        offset += len;
        if (offset > pdu_array->len) {
            DbgFprintf(outlogfile, PRINT_ERROR, "[-] SMB Incorrect negotiate conext length");
            return -1;
        }
        offset = PAD_TO_64BIT(offset);
    }

    return 0;
}

int process_dynamic_negotiate_pdu(struct smb_context* smb_context_inst, struct smb_pdu* pdu)
{
    struct negotiate_reply_msg* rep = (negotiate_reply_msg*)pdu->pdu_data;
    struct pdu_buffer* pdu_array = &smb_context_inst->recv_buf_array.pdu_array[smb_context_inst->recv_buf_array.pdu_array_size - 1];

    rep->security_buffer = &pdu_array->buf[IOV_OFFSET_NEG];

    if (rep->dialect_revision < SMB2_VERSION_0311 || !rep->negotiate_context_count)
        return 0;    

    int offset = rep->negotiate_context_offset - SMB_HEADER_SIZE - (SMB2_NEGOTIATE_REPLY_SIZE & 0xfffe);

    if (offset < 0 || offset > pdu_array->len)
        return -1;
    
    if (parse_negotiate_contexts(rep, pdu_array, offset, rep->negotiate_context_count))
        return -1;

    return 0;
}

struct smb_pdu *allocate_pdu(uint64_t session_id, uint8_t command, resp_handler_func resp_handler)
{

    char magic[4] = {(char)0xFE, 'S', 'M', 'B'};
    struct smb_pdu* pdu = (smb_pdu*)calloc(1, sizeof(struct smb_pdu));
    if (pdu == NULL) {
        DbgFprintf(outlogfile, PRINT_ERROR, "SMB Failed allocating buffer.");
        return NULL;
    }

    struct smb_header* hdr = &pdu->header;
    memcpy(hdr->protocol_id, magic, 4);
    memset(hdr->signature, 0, 16);

    hdr->struct_size = SMB_HEADER_SIZE;
    hdr->command = command;
    hdr->flags = 0;
    hdr->sync.process_id = 0xFEFF;
    hdr->credit_charge = 1;
    hdr->credit_request_response = MAX_CREDITS;

    switch (command) {
        case SMB_NEGOTIATE_MSG:
            break;
        default:
            hdr->session_id = session_id;
    }

    pdu->resp_handler = resp_handler;
    pdu->send_buf_array.pdu_array_size = 0;

    add_pdu_buffer(&pdu->send_buf_array, pdu->hdr, SMB_HEADER_SIZE, NULL);
 
    return pdu;
}

void free_pdu(struct smb_pdu* pdu)
{
    free_pdu_buffer(&pdu->send_buf_array);
    free_pdu_buffer(&pdu->recv_buf_array);

    free(pdu->pdu_data);
    free(pdu);
}

void encode_smb_header(struct smb_context *smb_context_inst, struct pdu_buffer *pdu_array,  struct smb_header *hdr)
{
    hdr->message_id = smb_context_inst->message_id++;
    if (hdr->credit_charge > 1)
        smb_context_inst->message_id += (hdr->credit_charge - 1);    

    memcpy(pdu_array->buf, hdr->protocol_id, 4);
    buf_set_uint16(pdu_array, 4, hdr->struct_size);
    buf_set_uint16(pdu_array, 6, hdr->credit_charge);
    buf_set_uint32(pdu_array, 8, hdr->status);
    buf_set_uint16(pdu_array, 12, hdr->command);
    buf_set_uint16(pdu_array, 14, hdr->credit_request_response);
    buf_set_uint32(pdu_array, 16, hdr->flags);
    buf_set_uint32(pdu_array, 20, hdr->next_command);
    buf_set_uint64(pdu_array, 24, hdr->message_id);

    if (hdr->flags & SMB2_FLAGS_ASYNC_COMMAND) {
        buf_set_uint64(pdu_array, 32, hdr->async.async_id);
    } else {
        buf_set_uint32(pdu_array, 32, hdr->sync.process_id);
        buf_set_uint32(pdu_array, 36, hdr->sync.tree_id);
    }

    buf_set_uint64(pdu_array, 40, hdr->session_id);
    memcpy(pdu_array->buf + 48, hdr->signature, 16);
}

int decode_smb_header(struct pdu_buffer *pdu_array, struct smb_header *hdr)
{
    static char smb_header[4] = {(char)0xFE, 'S', 'M', 'B'};

    if (pdu_array->len < SMB_HEADER_SIZE) {
        DbgFprintf(outlogfile, PRINT_ERROR, "[-] SMB header buffer too small");
        return -1;
    }
    if (memcmp(pdu_array->buf, smb_header, 4)) {
        DbgFprintf(outlogfile, PRINT_ERROR, "[-] SMB incorrect header signature");
        return -1;
    }

    memcpy(&hdr->protocol_id, pdu_array->buf, 4);
    buf_get_uint16(pdu_array, 4, &hdr->struct_size);
    buf_get_uint16(pdu_array, 6, &hdr->credit_charge);
    buf_get_uint32(pdu_array, 8, &hdr->status);
    buf_get_uint16(pdu_array, 12, &hdr->command);
    buf_get_uint16(pdu_array, 14, &hdr->credit_request_response);
    buf_get_uint32(pdu_array, 16, &hdr->flags);
    buf_get_uint32(pdu_array, 20, &hdr->next_command);
    buf_get_uint64(pdu_array, 24, &hdr->message_id);

    if (hdr->flags & SMB2_FLAGS_ASYNC_COMMAND) {
        buf_get_uint64(pdu_array, 32, &hdr->async.async_id);
    } else {
        buf_get_uint32(pdu_array, 32, &hdr->sync.process_id);
        buf_get_uint32(pdu_array, 36, &hdr->sync.tree_id);
    }
        
    buf_get_uint64(pdu_array, 40, &hdr->session_id);
    memcpy(&hdr->signature, pdu_array->buf + 48, 16);

    return 0;
}

void queue_pdu(struct smb_context *smb_context_inst, struct smb_pdu *pdu)
{
    struct smb_pdu *p = pdu;

    //Encode the header
    encode_smb_header(smb_context_inst, &p->send_buf_array.pdu_array[0], &p->header);    

    //Send the pdu and receive the response
    send_recv(smb_context_inst, pdu);

}


int is_error_in_resp(struct smb_context *smb_context_inst, struct smb_pdu *pdu)
{
    if ((smb_context_inst->hdr.status & SMB2_STATUS_SEVERITY_MASK) == SMB2_STATUS_SEVERITY_ERROR) {
            switch (smb_context_inst->hdr.status) {
                case SMB2_STATUS_MORE_PROCESSING_REQUIRED:
                        return 0;
                default:
                        return 1;
            }
    } 
    return 0;
}

int get_static_pdu_size(struct smb_context *smb_context_inst, struct smb_pdu *pdu)
{
    if (is_error_in_resp(smb_context_inst, pdu))
        return SMB_ERROR_REPLY_SIZE & 0xfffe;    

    switch (pdu->header.command) {
        case SMB_NEGOTIATE_MSG:
            return SMB2_NEGOTIATE_REPLY_SIZE;
        case SMB_SESSION_SETUP_MSG:
            return SMB_SESSION_SETUP_REPLY_SIZE;
    }
    return -1;
}

int process_static_pdu(struct smb_context *smb_context_inst, struct smb_pdu *pdu)
{
    if (is_error_in_resp(smb_context_inst, pdu))
         return process_static_pdu_error(smb_context_inst, pdu);    

    switch (pdu->header.command) {
        case SMB_NEGOTIATE_MSG:
            return process_static_negotiate_pdu(smb_context_inst, pdu);
        case SMB_SESSION_SETUP_MSG:
            return process_static_session_setup_pdu(smb_context_inst, pdu);
    }
    return 0;
}

int process_dynamic_session_setup_pdu(struct smb_context* smb_context_inst, struct smb_pdu* pdu)
{
    struct session_setup_reply_msg* rep = (session_setup_reply_msg*)pdu->pdu_data;
    struct pdu_buffer* pdu_array = &smb_context_inst->recv_buf_array.pdu_array[smb_context_inst->recv_buf_array.pdu_array_size - 1];

    rep->security_buffer = &pdu_array->buf[IOV_OFFSET_SESS];

    unsigned int offset = ((unsigned int*)(rep->security_buffer))[0xb];
    if (offset == 0 || offset % 2 > 0)
        return -1;
    
    //Get netbios domain
    short attr_type = ((short*)(rep->security_buffer))[offset / 2];
    short attr_val = ((short*)(rep->security_buffer))[(offset / 2) + 1];

    //Update offset
    offset += attr_val + 4;

    //Get netbios hostname
    attr_type = ((short*)(rep->security_buffer))[offset / 2];
    attr_val = ((short*)(rep->security_buffer))[(offset / 2) + 1];

    //Update offset
    offset += attr_val + 4;

    //Get dns domain
    attr_type = ((short*)(rep->security_buffer))[offset / 2];
    attr_val = ((short*)(rep->security_buffer))[(offset / 2) + 1];

    wchar_t* dns_domain = (wchar_t*)calloc(1, (size_t)attr_val + 2);
    if (dns_domain == NULL)
        return -1;

    memcpy(dns_domain, &rep->security_buffer[offset + 4], attr_val);
    set_server_domain(smb_context_inst, dns_domain);

    //Update offset
    offset += attr_val + 4;

    //Get dns hostname
    attr_type = ((short*)(rep->security_buffer))[offset / 2];
    attr_val = ((short*)(rep->security_buffer))[(offset / 2) + 1];

    wchar_t* dns_hostname = (wchar_t*)calloc(1, (size_t)attr_val + 2);
    if (dns_hostname == NULL)
        return -1;

    memcpy(dns_hostname, &rep->security_buffer[offset + 4], attr_val);
    set_server_hostname(smb_context_inst, dns_hostname);

    // Get OS information
    short major = rep->security_buffer[0x30];
    short minor = rep->security_buffer[0x31];
    short build = ((short*)(rep->security_buffer))[0x19];

    char* os_version = (char*)calloc(1, 64);
    if (os_version == NULL)
        return -1;

    snprintf(os_version, 64, "Windows %d.%d Build %d", major, minor, build);
    set_os_version(smb_context_inst, os_version);

    return 0;
}

int process_dynamic_pdu(struct smb_context *smb_context_inst, struct smb_pdu *pdu)
{
    if (is_error_in_resp(smb_context_inst, pdu))
        return process_dynamic_pdu_error(smb_context_inst, pdu);
    
    switch (pdu->header.command) {
        case SMB_NEGOTIATE_MSG:
            return process_dynamic_negotiate_pdu(smb_context_inst, pdu);
        case SMB_SESSION_SETUP_MSG:
            return process_dynamic_session_setup_pdu(smb_context_inst, pdu);
    }
    return 0;
}

struct pdu_buffer* add_pdu_buffer(struct pdu_buffer_array* pdu_array_inst, uint8_t* buf, int len, void (*free)(void*))
{
    struct pdu_buffer* pdu_array = &pdu_array_inst->pdu_array[pdu_array_inst->pdu_array_size];

    pdu_array_inst->pdu_array[pdu_array_inst->pdu_array_size].buf = buf;
    pdu_array_inst->pdu_array[pdu_array_inst->pdu_array_size].len = len;
    pdu_array_inst->pdu_array[pdu_array_inst->pdu_array_size].free = free;
    pdu_array_inst->total_size += len;
    pdu_array_inst->pdu_array_size++;

    return pdu_array;
}


void free_pdu_buffer(struct pdu_buffer_array* pdu_array_inst)
{
    for (uint32_t i = 0; i < pdu_array_inst->pdu_array_size; i++)
        if (pdu_array_inst->pdu_array[i].free)
            pdu_array_inst->pdu_array[i].free(pdu_array_inst->pdu_array[i].buf);

    pdu_array_inst->pdu_array_size = 0;
    pdu_array_inst->total_size = 0;
    pdu_array_inst->num_done = 0;
}