#pragma once

#include <stdint.h>
#include "smb.h"

BOOL pad_to_64bit(struct pdu_buffer_array* v);

BOOL buf_get_uint8(struct pdu_buffer* pdu_array, int offset, uint8_t* value);
BOOL buf_get_uint16(struct pdu_buffer* pdu_array, int offset, uint16_t* value);
BOOL buf_get_uint32(struct pdu_buffer* pdu_array, int offset, uint32_t* value);
BOOL buf_get_uint64(struct pdu_buffer* pdu_array, int offset, uint64_t* value);

BOOL buf_set_uint8(struct pdu_buffer* pdu_array, int offset, uint8_t value);
BOOL buf_set_uint16(struct pdu_buffer* pdu_array, int offset, uint16_t value);
BOOL buf_set_uint32(struct pdu_buffer* pdu_array, int offset, uint32_t value);
BOOL buf_set_uint64(struct pdu_buffer* pdu_array, int offset, uint64_t value);