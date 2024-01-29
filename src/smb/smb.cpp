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

#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "smb.h"
#include "ws2tcpip.h"
#include "smb_socket.h"
#include "smb_pdu.h"
#include "smb_utils.h"
#include "..\utils.h"
#include "..\debug.h"

void free_ntlm_buffer(struct auth_data* auth)
{
    if (auth) {
        if (auth->ntlm_buf)
            free(auth->ntlm_buf);
        if (auth->buf)
            free(auth->buf);

        free(auth);
    }
}

struct auth_data* init_ntlm_buffer()
{
    struct auth_data* auth_data_inst = NULL;

    auth_data_inst = (auth_data*)calloc(1, sizeof(struct auth_data));
    if (auth_data_inst == NULL) {
        return NULL;
    }

    char client_challenge[8];
    for (int i = 0; i < 8; i++)
        client_challenge[i] = rand() & 0xff;

    auth_data_inst->client_challenge = client_challenge;
    memset(auth_data_inst->exported_session_key, 0, SMB2_KEY_SIZE);

    return auth_data_inst;
}

int encode_ntlm_buffer(const void* buffer, size_t size, void* ptr)
{
    struct auth_data* auth_data_inst = (auth_data*)ptr;

    if (size + auth_data_inst->len > auth_data_inst->allocated) {
        unsigned char* tmp = auth_data_inst->buf;

        auth_data_inst->allocated = 2 * ((size + auth_data_inst->allocated + 256) & ~0xff);
        auth_data_inst->buf = (unsigned char*)malloc(auth_data_inst->allocated);
        if (auth_data_inst->buf == NULL) {
            free(tmp);
            return -1;
        }
        memcpy(auth_data_inst->buf, tmp, auth_data_inst->len);
        free(tmp);
    }

    memcpy(auth_data_inst->buf + auth_data_inst->len, buffer, size);
    auth_data_inst->len += size;

    return 0;
}

int ntlm_negotiate_message(struct auth_data* auth_data)
{
    unsigned char ntlm[32];

    memset(ntlm, 0, 32);
    memcpy(ntlm, "NTLMSSP", 8);

    uint32_t u32 = htole32(NEGOTIATE_MESSAGE);
    memcpy(&ntlm[8], &u32, 4);

    u32 = NTLMSSP_NEGOTIATE_128 |
        NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY |
        NTLMSSP_NEGOTIATE_SEAL |
        NTLMSSP_REQUEST_TARGET | NTLMSSP_NEGOTIATE_OEM |
        NTLMSSP_NEGOTIATE_UNICODE;
    u32 = htole32(u32);
    memcpy(&ntlm[12], &u32, 4);

    if (encode_ntlm_buffer(&ntlm[0], 32, auth_data) < 0)
        return -1;
    
    return 0;
}

int ntlmssp_generate_blob(struct auth_data* auth_data, unsigned char** output_buf, uint16_t* output_len)
{
    int ret = ntlm_negotiate_message(auth_data);
    if (ret == -1)
        return ret;

    *output_buf = auth_data->buf;
    *output_len = auth_data->len;

    return 0;
}

void free_smb_context(struct smb_context* smb_context_inst)
{
    if (smb_context_inst == NULL) 
        return;    

    if (smb_context_inst->fd != -1) {
        close_wrap(smb_context_inst->fd);
        smb_context_inst->fd = -1;
    }
   
    free_pdu_buffer(&smb_context_inst->recv_buf_array);

    if (smb_context_inst->session_key) {
        free(smb_context_inst->session_key);
        smb_context_inst->session_key = NULL;
    }

    free(smb_context_inst);
}

void set_os_version(struct smb_context* smb_context_inst, const char* os_version)
{
    if (os_version == NULL)
        return;    

    smb_context_inst->os_version = std::string(os_version);
}

void set_server_hostname(struct smb_context* smb_context_inst, const wchar_t* hostname)
{
    if (hostname == NULL)
        return;

    smb_context_inst->server_hostname = ws2s(std::wstring(hostname));
}

void set_server_domain(struct smb_context* smb_context_inst, const wchar_t* domain)
{
    if (domain == NULL)
        return;
    
    smb_context_inst->server_domain = ws2s(std::wstring(domain));
}

std::string smb_context_to_string(struct smb_context* smb_context_inst)
{
    std::string ret_str;

    //Add Operating System
    ret_str.assign(smb_context_inst->os_version);

    //Add Hostname
    ret_str.append(" (name: ");
    ret_str.append(smb_context_inst->server_hostname);
    ret_str.append(")");

    //Add Domain
    ret_str.append(" (domain: ");
    ret_str.append(smb_context_inst->server_domain);
    ret_str.append(")");

    return ret_str;
}

int process_dynamic_pdu_error(struct smb_context* smb_context_inst, struct smb_pdu* pdu)
{
    struct error_reply_msg* rep = (error_reply_msg*)pdu->pdu_data;
    struct pdu_buffer* pdu_array = &smb_context_inst->recv_buf_array.pdu_array[smb_context_inst->recv_buf_array.pdu_array_size - 1];

    rep->error_data = &pdu_array->buf[0];

    return 0;
}

int process_static_pdu_error(struct smb_context* smb_context_inst, struct smb_pdu* pdu)
{
    struct pdu_buffer* pdu_array = &smb_context_inst->recv_buf_array.pdu_array[smb_context_inst->recv_buf_array.pdu_array_size - 1];
    uint16_t struct_size;

    struct error_reply_msg* rep = (error_reply_msg*)malloc(sizeof(*rep));
    if (rep == NULL) {
        DbgFprintf(outlogfile, PRINT_ERROR, "SMB Failed allocating buffer.");
        return -1;
    }
    pdu->pdu_data = rep;

    buf_get_uint16(pdu_array, 0, &struct_size);
    if (struct_size != SMB_ERROR_REPLY_SIZE ||
        (struct_size & 0xfffe) != pdu_array->len) {
        DbgFprintf(outlogfile, PRINT_ERROR, "SMB Wrong error pdu size. Expected %d, got %d", SMB_ERROR_REPLY_SIZE, (int)pdu_array->len);
        return -1;
    }

    buf_get_uint8(pdu_array, 2, &rep->error_context_count);
    buf_get_uint32(pdu_array, 4, &rep->byte_count);

    return rep->byte_count;
}

int encode_preauth_context(struct smb_pdu* pdu)
{
    uint32_t data_len = PAD_TO_64BIT(38);
    uint32_t len = 8 + data_len;
    uint8_t* buf = (uint8_t *)malloc(len);
    if (buf == NULL) {
        DbgFprintf(outlogfile, PRINT_ERROR, "SMB Failed allocating buffer.");
        return -1;
    }
    memset(buf, 0, len);

    struct pdu_buffer* pdu_array = add_pdu_buffer( &pdu->send_buf_array, buf, len, free);
    buf_set_uint16(pdu_array, 0, SMB2_PREAUTH_INTEGRITY_CAP);
    buf_set_uint16(pdu_array, 2, data_len);
    buf_set_uint16(pdu_array, 8, 1);
    buf_set_uint16(pdu_array, 10, 32);
    buf_set_uint16(pdu_array, 12, SMB2_HASH_SHA_512);

    uint8_t salt[SMB2_SALT_SIZE];
    for (uint32_t i = 0; i < SMB2_SALT_SIZE; i++)
        salt[i] = rand() & 0xff;

    for (uint32_t i = 0; i < SMB2_SALT_SIZE; i++)
        buf_set_uint8(pdu_array, 14 + i, salt[i]);
    
    return 0;
}

int encode_encryption_context(struct smb_pdu* pdu)
{
    uint32_t data_len = PAD_TO_64BIT(4);
    uint32_t len = 8 + data_len;
    len = PAD_TO_64BIT(len);
    uint8_t* buf = (uint8_t *)malloc(len);
    if (buf == NULL) {
        DbgFprintf(outlogfile, PRINT_ERROR, "SMB Failed allocating buffer.");
        return -1;
    }
    memset(buf, 0, len);

    struct pdu_buffer* pdu_array = add_pdu_buffer(&pdu->send_buf_array, buf, len, free);
    buf_set_uint16(pdu_array, 0, SMB2_ENCRYPTION_CAP);
    buf_set_uint16(pdu_array, 2, data_len);
    buf_set_uint16(pdu_array, 8, 1);
    buf_set_uint16(pdu_array, 10, SMB2_ENCRYPTION_AES_128_CCM);

    return 0;
}

int encode_negotiate_pdu(uint16_t smb_version, struct smb_pdu* pdu, struct negotiate_request_msg* req)
{
    uint32_t len = SMB_NEGOTIATE_REQUEST_SIZE + req->dialect_count * sizeof(uint16_t);
    len = PAD_TO_32BIT(len);
    if (smb_version == SMB2_VERSION_ANY || smb_version == SMB2_VERSION_ANY3 || smb_version == SMB2_VERSION_0311) {
        if (len & 0x04)
            len += 4;        
    }

    uint8_t* buf = (uint8_t * )calloc(len, sizeof(uint8_t));
    if (buf == NULL) {
        DbgFprintf(outlogfile, PRINT_ERROR, "SMB Failed allocating buffer.");
        return -1;
    }

    struct pdu_buffer* pdu_array = add_pdu_buffer(&pdu->send_buf_array, buf, len, free);

    if (smb_version == SMB2_VERSION_ANY ||
        smb_version == SMB2_VERSION_ANY3 ||
        smb_version == SMB2_VERSION_0311) {
        req->negotiate_context_offset = len + SMB_HEADER_SIZE;

        if (encode_preauth_context(pdu))
            return -1;
        
        req->negotiate_context_count++;

        if (encode_encryption_context(pdu))
            return -1;
        
        req->negotiate_context_count++;
    }

    buf_set_uint16(pdu_array, 0, SMB_NEGOTIATE_REQUEST_SIZE);
    buf_set_uint16(pdu_array, 2, req->dialect_count);
    buf_set_uint16(pdu_array, 4, req->security_mode);
    buf_set_uint32(pdu_array, 8, req->capabilities);
    memcpy(pdu_array->buf + 12, req->client_guid, 16);
    buf_set_uint32(pdu_array, 28, req->negotiate_context_offset);
    buf_set_uint16(pdu_array, 32, req->negotiate_context_count);
    for (uint32_t i = 0; i < req->dialect_count; i++)
        buf_set_uint16(pdu_array, 36 + i * sizeof(uint16_t), req->dialects[i]);
    
    return 0;
}

int encode_session_setup_request(struct smb_pdu* pdu, struct session_setup_request_msg* req)
{
    uint32_t len = SMB_SESSION_SETUP_REQUEST_SIZE & 0xfffffffe;
    uint8_t* buf = (uint8_t*)calloc(len, sizeof(uint8_t));
    if (buf == NULL) {
        DbgFprintf(outlogfile, PRINT_ERROR, "SMB Failed allocating buffer.");
        return -1;
    }

    struct pdu_buffer* pdu_array = add_pdu_buffer(&pdu->send_buf_array, buf, len, free);

    buf_set_uint16(pdu_array, 0, SMB_SESSION_SETUP_REQUEST_SIZE);
    buf_set_uint8(pdu_array, 2, req->flags);
    buf_set_uint8(pdu_array, 3, req->security_mode);
    buf_set_uint32(pdu_array, 4, req->capabilities);
    buf_set_uint32(pdu_array, 8, req->channel);
    buf_set_uint16(pdu_array, 12, SMB_HEADER_SIZE + 24);
    buf_set_uint16(pdu_array, 14, req->security_buffer_length);
    buf_set_uint64(pdu_array, 16, req->previous_session_id);

    buf = (uint8_t *)malloc(req->security_buffer_length);
    if (buf == NULL) {
        DbgFprintf(outlogfile, PRINT_ERROR, "SMB Failed allocating buffer.");
        return -1;
    }
    memcpy(buf, req->security_buffer, req->security_buffer_length);
    pdu_array = add_pdu_buffer(&pdu->send_buf_array, buf, req->security_buffer_length, free);
    return 0;
}

struct smb_pdu* build_negotiate_pdu(struct smb_context* smb_context_inst, struct negotiate_request_msg* req)
{
    struct smb_pdu* pdu = allocate_pdu(smb_context_inst->session_id, SMB_NEGOTIATE_MSG, negotiate_cb);
    if (pdu == NULL)
        return NULL;    

    if (encode_negotiate_pdu(smb_context_inst->version, pdu, req)) {
        free_pdu(pdu);
        return NULL;
    }

    if (pad_to_64bit(&pdu->send_buf_array) != 0) {
        free_pdu(pdu);
        return NULL;
    }

    return pdu;
}

struct smb_pdu* build_session_setup_pdu(uint64_t session_id, struct session_setup_request_msg* req)
{
    struct smb_pdu* pdu = allocate_pdu(session_id, SMB_SESSION_SETUP_MSG, session_setup_cb);
    if (pdu == NULL)
        return NULL;    

    if (encode_session_setup_request(pdu, req)) {
        free_pdu(pdu);
        return NULL;
    }

    if (pad_to_64bit(&pdu->send_buf_array) != 0) {
        free_pdu(pdu);
        return NULL;
    }

    return pdu;
}

void close_smb_context(struct smb_context* smb_context_inst)
{
    if (smb_context_inst == NULL)
        return;    

    if (smb_context_inst->fd != -1) {     
        close_wrap(smb_context_inst->fd);
        smb_context_inst->fd = -1;
    }

    smb_context_inst->message_id = 0;
    smb_context_inst->session_id = 0;

    if (smb_context_inst->session_key) {
        free(smb_context_inst->session_key);
        smb_context_inst->session_key = NULL;
    }
}

void session_setup_cb(struct smb_context* smb_context_inst, int status, void* msg_data)
{
    close_smb_context(smb_context_inst);
}

int send_session_setup_request(struct smb_context* smb_context_inst, auth_data* auth_ptr)
{
    struct session_setup_request_msg req;
    memset(&req, 0, sizeof(struct session_setup_request_msg));
    req.security_mode = SMB2_NEGOTIATE_SIGNING_ENABLED;

    if (ntlmssp_generate_blob(auth_ptr, &req.security_buffer, &req.security_buffer_length) < 0) {
        close_smb_context(smb_context_inst);
        return -1;
    }

    struct smb_pdu* pdu = build_session_setup_pdu(smb_context_inst->session_id, &req);
    if (pdu == NULL) {
        close_smb_context(smb_context_inst);
        return -ENOMEM;
    }
    queue_pdu(smb_context_inst, pdu);

    return 0;
}

void negotiate_cb(struct smb_context* smb_context_inst, int status, void* msg_data)
{
    struct negotiate_reply_msg* rep = (negotiate_reply_msg*)msg_data;
    int ret;

    if (status != SMB2_STATUS_SUCCESS) {
        close_smb_context(smb_context_inst);
        DbgFprintf(outlogfile, PRINT_ERROR, "[-] SMB Negotiate failed.");
        return;
    }

    /* update the context with the server capabilities */
    if (rep->dialect_revision > SMB2_VERSION_0202 && (rep->capabilities & SMB2_GLOBAL_CAP_LARGE_MTU))
        smb_context_inst->smb_capabilities = 1;        
        
    auth_data* auth_ptr = init_ntlm_buffer();
    if (auth_ptr == NULL) {
        close_smb_context(smb_context_inst);
        return;
    }

    if ((ret = send_session_setup_request(smb_context_inst, auth_ptr)) < 0) {
        close_smb_context(smb_context_inst);
        return;
    }

    //Free memory
    if (auth_ptr)
        free_ntlm_buffer(auth_ptr);
}

void send_negotiate_req(struct smb_context* smb_context_inst)
{
    struct negotiate_request_msg req;

    memset(&req, 0, sizeof(struct negotiate_request_msg));
    req.capabilities = SMB2_GLOBAL_CAP_LARGE_MTU;
    if (smb_context_inst->version == SMB2_VERSION_ANY ||
        smb_context_inst->version == SMB2_VERSION_ANY3 ||
        smb_context_inst->version == SMB2_VERSION_0300 ||
        smb_context_inst->version == SMB2_VERSION_0302 ||
        smb_context_inst->version == SMB2_VERSION_0311) {
        req.capabilities |= SMB2_GLOBAL_CAP_ENCRYPTION;
    }
    req.security_mode = SMB2_NEGOTIATE_SIGNING_ENABLED;
    switch (smb_context_inst->version) {
        case SMB2_VERSION_ANY:
            req.dialect_count = 5;
            req.dialects[0] = SMB2_VERSION_0202;
            req.dialects[1] = SMB2_VERSION_0210;
            req.dialects[2] = SMB2_VERSION_0300;
            req.dialects[3] = SMB2_VERSION_0302;
            req.dialects[4] = SMB2_VERSION_0311;
            break;
        case SMB2_VERSION_ANY2:
            req.dialect_count = 2;
            req.dialects[0] = SMB2_VERSION_0202;
            req.dialects[1] = SMB2_VERSION_0210;
            break;
        case SMB2_VERSION_ANY3:
            req.dialect_count = 3;
            req.dialects[0] = SMB2_VERSION_0300;
            req.dialects[1] = SMB2_VERSION_0302;
            req.dialects[2] = SMB2_VERSION_0311;
            break;
        case SMB2_VERSION_0202:
        case SMB2_VERSION_0210:
        case SMB2_VERSION_0300:
        case SMB2_VERSION_0302:
        case SMB2_VERSION_0311:
            req.dialect_count = 1;
            req.dialects[0] = smb_context_inst->version;
            break;
    }
                
    struct smb_pdu* pdu = build_negotiate_pdu(smb_context_inst, &req);
    if (pdu == NULL)
        return;    

    queue_pdu(smb_context_inst, pdu);
}

struct smb_context* get_srv_info(std::string host) {

    WSADATA wsaData;
    struct smb_context* smb_context_inst = (smb_context*)calloc(1, sizeof(struct smb_context));
    if (smb_context_inst == NULL)
        return NULL;

    //Init socket descriptor
    smb_context_inst->fd = -1;

    if (host.empty()) {
        DbgFprintf(outlogfile, PRINT_ERROR, "[-] No server name provided");
        return NULL;
    }

    // Initialize Winsock
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        printf("[-] WSAStartup failed: %d\n", iResult);
        return NULL;
    }

    //Connect to the SMB service
    connect_to_server(smb_context_inst, host);

    // Cleanup Winsock
    WSACleanup();

    return smb_context_inst;

}