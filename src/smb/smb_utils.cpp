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

#include "smb_utils.h"
#include "smb_pdu.h"

BOOL buf_set_uint8(struct pdu_buffer* pdu_array, int offset, uint8_t value)
{
    if (offset + sizeof(uint8_t) > pdu_array->len)
        return -1;

    pdu_array->buf[offset] = value;
    return 0;
}

BOOL buf_set_uint16(struct pdu_buffer* pdu_array, int offset, uint16_t value)
{
    if (offset + sizeof(uint16_t) > pdu_array->len)
        return -1;

    *(uint16_t*)(pdu_array->buf + offset) = htole16(value);
    return 0;
}

BOOL buf_set_uint32(struct pdu_buffer* pdu_array, int offset, uint32_t value)
{
    if (offset + sizeof(uint32_t) > pdu_array->len)
        return -1;

    *(uint32_t*)(pdu_array->buf + offset) = htole32(value);
    return 0;
}

BOOL buf_set_uint64(struct pdu_buffer* pdu_array, int offset, uint64_t value)
{
    if (offset + sizeof(uint64_t) > pdu_array->len)
        return -1;

    value = htole64(value);
    memcpy(pdu_array->buf + offset, &value, 8);
    return 0;
}

BOOL buf_get_uint8(struct pdu_buffer* pdu_array, int offset, uint8_t* value)
{
    if (offset + sizeof(uint8_t) > pdu_array->len)
        return -1;

    *value = pdu_array->buf[offset];
    return 0;
}

BOOL buf_get_uint16(struct pdu_buffer* pdu_array, int offset, uint16_t* value)
{
    uint16_t tmp;

    if (offset + sizeof(uint16_t) > pdu_array->len)
        return -1;

    memcpy(&tmp, pdu_array->buf + offset, sizeof(uint16_t));
    *value = le16toh(tmp);
    return 0;
}

BOOL buf_get_uint32(struct pdu_buffer* pdu_array, int offset, uint32_t* value)
{
    uint32_t tmp;

    if (offset + sizeof(uint32_t) > pdu_array->len)
        return -1;

    memcpy(&tmp, pdu_array->buf + offset, sizeof(uint32_t));
    *value = le32toh(tmp);
    return 0;
}

BOOL buf_get_uint64(struct pdu_buffer* pdu_array, int offset, uint64_t* value)
{
    uint64_t tmp;

    if (offset + sizeof(uint64_t) > pdu_array->len)
        return -1;

    memcpy(&tmp, pdu_array->buf + offset, sizeof(uint64_t));
    *value = le64toh(tmp);
    return 0;
}

BOOL pad_to_64bit(struct pdu_buffer_array* pdu_buffer_inst)
{
    static uint8_t zero_bytes[7];
    int len = 0;

    for (uint32_t i = 0; i < pdu_buffer_inst->pdu_array_size; i++)
        len += pdu_buffer_inst->pdu_array[i].len;

    if ((len & 0x07) == 0)
        return 0;

    if (add_pdu_buffer(pdu_buffer_inst, &zero_bytes[0], 8 - (len & 0x07), NULL) == NULL)
        return -1;

    return 0;
}