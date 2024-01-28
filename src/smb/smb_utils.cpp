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