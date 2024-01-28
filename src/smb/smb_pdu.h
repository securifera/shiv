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
