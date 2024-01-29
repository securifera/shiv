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
#include <string>

#ifndef discard_const
#define discard_const(ptr) ((void *)((intptr_t)(ptr)))
#endif

#define PAD_TO_32BIT(len) ((len + 0x03) & 0xfffffffc)
#define PAD_TO_64BIT(len) ((len + 0x07) & 0xfffffff8)

#define SMB2_FLAGS_SERVER_TO_REDIR    0x00000001
#define SMB2_FLAGS_ASYNC_COMMAND      0x00000002
#define SMB2_FLAGS_RELATED_OPERATIONS 0x00000004

#define SMB_NEGOTIATE_MSG 0
#define SMB_SESSION_SETUP_MSG 1

#define SMB_STATIC_PDU_LEN_SIZE 4
#define SMB_HEADER_SIZE 64
#define SMB2_SIGNATURE_SIZE 16
#define SMB2_KEY_SIZE 16
#define SMB2_MAX_VECTORS 256
#define SMB2_SALT_SIZE 32
#define SMB2_PREAUTH_HASH_SIZE  64
#define MAX_ERROR_SIZE 256

#define SMB2_NEGOTIATE_SIGNING_ENABLED  0x0001
#define SMB2_NEGOTIATE_SIGNING_REQUIRED 0x0002

#define SMB2_GLOBAL_CAP_LARGE_MTU          0x00000004
#define SMB2_GLOBAL_CAP_ENCRYPTION         0x00000040

#define SMB2_PREAUTH_INTEGRITY_CAP         0x0001
#define SMB2_ENCRYPTION_CAP                0x0002

#define SMB2_HASH_SHA_512                  0x0001
#define SMB2_PREAUTH_HASH_SIZE             64

#define SMB2_ENCRYPTION_AES_128_CCM        0x0001

#define SMB2_NEGOTIATE_REPLY_SIZE 65
#define SMB2_NEGOTIATE_MAX_DIALECTS 10

#define SMB2_STATUS_SUCCESS                            0x00000000
#define SMB2_STATUS_MORE_PROCESSING_REQUIRED           0xC0000016
#define SMB2_STATUS_CANCELLED                          0xC0000120
#define SMB2_STATUS_PENDING                            0x00000103
#define SMB2_STATUS_IO_TIMEOUT                         0xC00000B5

#define SMB_SESSION_SETUP_REQUEST_SIZE 25
#define SMB_SESSION_SETUP_REPLY_SIZE 9
#define SMB_CREATE_REQUEST_SIZE 57
#define SMB_ERROR_REPLY_SIZE 9
#define SMB_NEGOTIATE_REQUEST_SIZE 36

#define MAX_CREDITS 1024

#define NEGOTIATE_MESSAGE      0x00000001
#define CHALLENGE_MESSAGE      0x00000002

#define NTLMSSP_NEGOTIATE_128                              0x20000000
#define NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY         0x00080000
#define NTLMSSP_NEGOTIATE_SEAL                             0x00000020
#define NTLMSSP_REQUEST_TARGET                             0x00000004
#define NTLMSSP_NEGOTIATE_OEM                              0x00000002
#define NTLMSSP_NEGOTIATE_UNICODE                          0x00000001

#define SMB2_STATUS_SEVERITY_MASK    0xc0000000
#define SMB2_STATUS_SEVERITY_WARNING 0x80000000
#define SMB2_STATUS_SEVERITY_ERROR   0xc0000000

typedef void (*resp_handler_func)(struct smb_context* smb_context_inst, int status, void* data);

#define htole16(x) (x)
#define htole32(x) (x)
#define htole64(x) (x)

#define htobe16(x) _byteswap_ushort(x)
#define htobe32(x) _byteswap_ulong(x)

#define le16toh(x) (x)
#define le32toh(x) (x)
#define le64toh(x) (x)

#define be32toh(x) _byteswap_ulong(x)

struct auth_data {
    unsigned char* buf;
    int len;
    int allocated;

    int neg_result;
    unsigned char* ntlm_buf;
    int ntlm_len;

    const char* user;
    const char* password;
    const char* domain;
    const char* workstation;
    const char* client_challenge;

    uint8_t exported_session_key[SMB2_KEY_SIZE];
};

struct pdu_buffer {
    uint8_t* buf;
    size_t len;
    void (*free)(void*);
};

struct pdu_buffer_array {
    size_t num_done;
    size_t total_size;
    int pdu_array_size;
    struct pdu_buffer pdu_array[SMB2_MAX_VECTORS];
};

struct smb_async {
    uint64_t async_id;
};

struct smb_sync {
    uint32_t process_id;
    uint32_t tree_id;
};

struct smb_header {
    uint8_t protocol_id[4];
    uint16_t struct_size;
    uint16_t credit_charge;
    uint32_t status;
    uint16_t command;
    uint16_t credit_request_response;
    uint32_t flags;
    uint32_t next_command;
    uint64_t message_id;
    union {
        struct smb_async async;
        struct smb_sync sync;
    };
    uint64_t session_id;
    uint8_t signature[16];
};

struct smb_context {

    SOCKET fd;
    enum smb_negotiate_version version;

    uint64_t message_id;
    uint64_t session_id;
    uint8_t* session_key;
        
    struct pdu_buffer_array recv_buf_array;
    enum class SMB_RECV_STATE recv_state;

    uint32_t static_pdu_len;
    uint8_t header[SMB_HEADER_SIZE];
    struct smb_header hdr;

    size_t packet_pdu_offset;

    uint8_t smb_capabilities;
        
    //Server info
    std::string os_version;
    std::string server_hostname;
    std::string server_domain;

};

struct negotiate_request_msg {
    uint16_t dialect_count;
    uint16_t security_mode;
    uint32_t capabilities;
    uint8_t client_guid[16];
    uint32_t negotiate_context_offset;
    uint16_t negotiate_context_count;
    uint16_t dialects[SMB2_NEGOTIATE_MAX_DIALECTS];
};

struct negotiate_reply_msg {
    uint16_t security_mode;
    uint16_t dialect_revision;
    uint16_t cypher;
    uint8_t server_guid[16];
    uint32_t capabilities;
    uint32_t max_transact_size;
    uint32_t max_read_size;
    uint32_t max_write_size;
    uint64_t system_time;
    uint64_t server_start_time;
    uint32_t negotiate_context_offset;
    uint16_t negotiate_context_count;
    uint16_t security_buffer_length;
    uint16_t security_buffer_offset;
    uint8_t* security_buffer;
};

struct session_setup_request_msg {
    uint8_t flags;
    uint8_t security_mode;
    uint32_t capabilities;
    uint32_t channel;
    uint64_t previous_session_id;
    uint16_t security_buffer_length;
    uint8_t* security_buffer;
};

enum smb_negotiate_version {
    SMB2_VERSION_ANY = 0,
    SMB2_VERSION_ANY2 = 2,
    SMB2_VERSION_ANY3 = 3,
    SMB2_VERSION_0202 = 0x0202,
    SMB2_VERSION_0210 = 0x0210,
    SMB2_VERSION_0300 = 0x0300,
    SMB2_VERSION_0302 = 0x0302,
    SMB2_VERSION_0311 = 0x0311
};

struct session_setup_reply_msg {
    uint16_t session_flags;
    uint16_t security_buffer_length;
    uint16_t security_buffer_offset;
    uint8_t* security_buffer;
};

struct error_reply_msg {
    uint8_t error_context_count;
    uint32_t byte_count;
    uint8_t* error_data;
};

//Function prototypes
void send_negotiate_req(struct smb_context* smb_context_inst);
void negotiate_cb(struct smb_context* smb_context_inst, int status, void* command_data);
void session_setup_cb(struct smb_context* smb_context_inst, int status, void* command_data);
void free_smb_context(struct smb_context* smb_context_inst);

int process_static_pdu_error(struct smb_context* smb_context_inst, struct smb_pdu* pdu);
int process_dynamic_pdu_error(struct smb_context* smb_context_inst, struct smb_pdu* pdu);

void set_os_version(struct smb_context* smb_context_inst, const char* os_version);
void set_server_hostname(struct smb_context* smb_context_inst, const wchar_t* hostname);
void set_server_domain(struct smb_context* smb_context_inst, const wchar_t* domain);
std::string smb_context_to_string(struct smb_context* smb_context_inst);
struct smb_context* get_srv_info(std::string host);



