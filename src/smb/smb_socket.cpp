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

#include "smb.h"
#include "smb_socket.h"
#include "smb_pdu.h"
#include "..\debug.h"

int send_wrap(SOCKET sock, struct socket_buffer* sock_buffer, int nvecs)
{
    DWORD ret;

    int res = WSASend(sock, (LPWSABUF)sock_buffer, nvecs, &ret, 0, NULL, NULL);
    if (res == 0)
        return (int)ret;

    return -1;
}

int recv_wrap(SOCKET sock, struct socket_buffer* sock_buffer, int nvecs)
{
    DWORD ret;
    DWORD flags = 0;

    int res = WSARecv(sock, (LPWSABUF)sock_buffer, nvecs, &ret, &flags, NULL, NULL);
    if (res == 0)
        return (int)ret;

    return -1;
}

 int close_wrap(SOCKET sock)
{
    return closesocket(sock);
}

int write_to_socket(struct smb_context* smb_context_inst, struct smb_pdu* pdu)
{
    if (smb_context_inst->fd == -1) {
        DbgFprintf(outlogfile, PRINT_ERROR, "[-] SMB failed writing to socket. Not connected to server.");
        return -1;
    }

    if (pdu == NULL) {
        DbgFprintf(outlogfile, PRINT_ERROR, "[-] SMB failed writing to socket. NULL PDU");
        return -1;
    }

    struct socket_buffer pdu_array[SMB2_MAX_VECTORS];
    int pdu_array_size = 1;
    uint32_t buffer_len = 0;

    struct smb_pdu* tmp_pdu = pdu;
    for (uint32_t i = 0; i < tmp_pdu->send_buf_array.pdu_array_size; i++, pdu_array_size++) {
        pdu_array[pdu_array_size].buffer = tmp_pdu->send_buf_array.pdu_array[i].buf;
        pdu_array[pdu_array_size].buffer_len = tmp_pdu->send_buf_array.pdu_array[i].len;
        buffer_len += tmp_pdu->send_buf_array.pdu_array[i].len;
    }

    //Add length
    uint32_t tmp_buf_len = htobe32(buffer_len);
    pdu_array[0].buffer = &tmp_buf_len;
    pdu_array[0].buffer_len = SMB_STATIC_PDU_LEN_SIZE;

    struct socket_buffer* tmpiov = pdu_array;

    //Skip already sent buffers
    size_t num_done = pdu->send_buf_array.num_done;
    while (num_done >= tmpiov->buffer_len) {
        num_done -= tmpiov->buffer_len;
        tmpiov++;
        pdu_array_size--;
    }

    //Fixup buffers
    tmpiov->buffer = (char*)tmpiov->buffer + num_done;
    tmpiov->buffer_len -= num_done;

    SSIZE_T count = send_wrap(smb_context_inst->fd, tmpiov, pdu_array_size);
    if (count == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;

        DbgFprintf(outlogfile, PRINT_ERROR, "[-] SMB Error when writing to socket :%d", errno);
        return -1;
    }

    pdu->send_buf_array.num_done += count;

    return 0;
}

int read_from_socket(struct smb_context* smb_context_inst, struct smb_pdu* pdu)
{
    struct socket_buffer pdu_array[SMB2_MAX_VECTORS];
    struct socket_buffer* buffer_inst;
    int pdu_array_size;
    SSIZE_T count, len;

read_more_data:
    size_t num_done = smb_context_inst->recv_buf_array.num_done;

    //Copy into temp buffers
    pdu_array_size = smb_context_inst->recv_buf_array.pdu_array_size;
    for (uint32_t i = 0; i < pdu_array_size; i++) {
        pdu_array[i].buffer = smb_context_inst->recv_buf_array.pdu_array[i].buf;
        pdu_array[i].buffer_len = smb_context_inst->recv_buf_array.pdu_array[i].len;
    }
    buffer_inst = pdu_array;

    //Skip buffers already read
    while (num_done >= buffer_inst->buffer_len) {
        num_done -= buffer_inst->buffer_len;
        buffer_inst++;
        pdu_array_size--;
    }

    //Fixup buffers
    buffer_inst->buffer = (char*)buffer_inst->buffer + num_done;
    buffer_inst->buffer_len -= num_done;

    //Read into buffers
    count = recv_wrap(smb_context_inst->fd, (socket_buffer*)buffer_inst, pdu_array_size);
    if (count < 0) {
        int err = WSAGetLastError();
        if (err == WSAEINTR || err == WSAEWOULDBLOCK)
            return 0;

        DbgFprintf(outlogfile, PRINT_ERROR, "[-] SMB failed reading from socket. Error: %d", err);
        return -1;
    }

    if (count == 0)
        return -1;
    
    smb_context_inst->recv_buf_array.num_done += count;

    if (smb_context_inst->recv_buf_array.num_done < smb_context_inst->recv_buf_array.total_size)
        goto read_more_data;


    switch (smb_context_inst->recv_state) {

        case SMB_RECV_STATE::SMB2_RECV_SPL:
                smb_context_inst->static_pdu_len = be32toh(smb_context_inst->static_pdu_len);
                smb_context_inst->recv_state = SMB_RECV_STATE::SMB2_RECV_HEADER;
                add_pdu_buffer(&smb_context_inst->recv_buf_array, &smb_context_inst->header[0], SMB_HEADER_SIZE, NULL);
                goto read_more_data;
        case SMB_RECV_STATE::SMB2_RECV_HEADER:

            if (decode_smb_header(&smb_context_inst->recv_buf_array.pdu_array[smb_context_inst->recv_buf_array.pdu_array_size - 1], &smb_context_inst->hdr) != 0) {
                DbgFprintf(outlogfile, PRINT_ERROR, "Failed decoding smb header");
                return -1;
            }

            //Save offset
            smb_context_inst->packet_pdu_offset = smb_context_inst->recv_buf_array.num_done;
            
            if (!(smb_context_inst->hdr.flags & SMB2_FLAGS_SERVER_TO_REDIR)) {
                DbgFprintf(outlogfile, PRINT_ERROR, "[-] SMB Failed reply");
                return -1;
            }

            len = get_static_pdu_size(smb_context_inst, pdu);
            if (len < 0) {
                DbgFprintf(outlogfile, PRINT_ERROR, "[-] SMB Unable to determine PDU size");
                return -1;
            }

            smb_context_inst->recv_state = SMB_RECV_STATE::SMB2_RECV_STATIC;
            add_pdu_buffer(&smb_context_inst->recv_buf_array, (uint8_t*)malloc(len & 0xfffe), len & 0xfffe, free);
            goto read_more_data;

        case SMB_RECV_STATE::SMB2_RECV_STATIC:
            len = process_static_pdu(smb_context_inst, pdu);
            if (len < 0) {
                DbgFprintf(outlogfile, PRINT_ERROR, "[-] SMB Failed parsing static pdu.");
                return -1;
            }

            //Add buffers
            if (len && len > 0) {
                smb_context_inst->recv_state = SMB_RECV_STATE::SMB2_RECV_DYNAMIC;
                add_pdu_buffer(&smb_context_inst->recv_buf_array, (uint8_t*)malloc(len), len, free);
                goto read_more_data;                
            }

            //Check padding
            if (smb_context_inst->hdr.next_command)
                len = smb_context_inst->hdr.next_command - (SMB_HEADER_SIZE + smb_context_inst->recv_buf_array.num_done - smb_context_inst->packet_pdu_offset);
            else
                len = (size_t)smb_context_inst->static_pdu_len + SMB_STATIC_PDU_LEN_SIZE - smb_context_inst->recv_buf_array.num_done;

            if (len < 0) {
                DbgFprintf(outlogfile, PRINT_ERROR, "[-] SMB Wrong PAD");
                return -1;
            }

            if (len > 0) {
                //Add padding
                smb_context_inst->recv_state = SMB_RECV_STATE::SMB2_RECV_PAD;
                add_pdu_buffer(&smb_context_inst->recv_buf_array, (uint8_t*)malloc(len), len, free);
                goto read_more_data;
            }
            break;
        case SMB_RECV_STATE::SMB2_RECV_DYNAMIC:
            if (process_dynamic_pdu(smb_context_inst, pdu) < 0) {
                DbgFprintf(outlogfile, PRINT_ERROR, "SMB Failed parsing dynamic pdu.");
                return -1;
            }

            //Check padding
            if (smb_context_inst->hdr.next_command)
                len = smb_context_inst->hdr.next_command - (SMB_HEADER_SIZE + smb_context_inst->recv_buf_array.num_done - smb_context_inst->packet_pdu_offset);
            else
                len = (size_t)smb_context_inst->static_pdu_len + SMB_STATIC_PDU_LEN_SIZE - smb_context_inst->recv_buf_array.num_done;
            
            if (len < 0) {
                DbgFprintf(outlogfile, PRINT_ERROR, "[-] SMB Wrong PAD");
                return -1;
            }
            if (len > 0) {
                smb_context_inst->recv_state = SMB_RECV_STATE::SMB2_RECV_PAD;
                add_pdu_buffer(&smb_context_inst->recv_buf_array, (uint8_t*)malloc(len), len, free);
                goto read_more_data;
            }
            break;

        case SMB_RECV_STATE::SMB2_RECV_PAD:
            break;
        default:
            return 0;
    }

    if (smb_context_inst->recv_buf_array.pdu_array_size < 2) {
        DbgFprintf(outlogfile, PRINT_ERROR, "[-] SMB Wrong number of buffers in PDU.");
        return -1;
    }

    pdu->resp_handler(smb_context_inst, smb_context_inst->hdr.status, pdu->pdu_data);
    free_pdu(pdu);

    smb_context_inst->recv_buf_array.num_done = 0;

    return 0;
}

int read_from_socket_wrap(struct smb_context* smb_context_inst, struct smb_pdu* pdu)
{ 
    smb_context_inst->recv_state = SMB_RECV_STATE::SMB2_RECV_SPL;
    smb_context_inst->static_pdu_len = 0;

    free_pdu_buffer(&smb_context_inst->recv_buf_array);
    add_pdu_buffer(&smb_context_inst->recv_buf_array, (uint8_t*)&smb_context_inst->static_pdu_len, SMB_STATIC_PDU_LEN_SIZE, NULL);

    return read_from_socket(smb_context_inst, pdu);
}

int send_recv(struct smb_context* smb_context_inst, struct smb_pdu* pdu) {

    int ret = 0;

    if (write_to_socket(smb_context_inst, pdu) != 0)
        return -1;    

    if (read_from_socket_wrap(smb_context_inst, pdu) != 0)
        ret = -1;    

    return ret;
}

int connect_wrap(const struct addrinfo *ai, int *fd_out)
{
    int family, fd;
    socklen_t socksize;
    struct sockaddr_storage ss;

    memset(&ss, 0, sizeof(ss));
    switch (ai->ai_family) {
        case AF_INET:
            socksize = sizeof(struct sockaddr_in);
            memcpy(&ss, ai->ai_addr, socksize);
            break;
        case AF_INET6:
            socksize = sizeof(struct sockaddr_in6);
            memcpy(&ss, ai->ai_addr, socksize);
            break;
        default:
            DbgFprintf(outlogfile, PRINT_ERROR, "[-] SMB Unknown address family");
            return -EINVAL;

    }
    family = ai->ai_family;

    fd = socket(family, SOCK_STREAM, 0);
    if (fd == -1) {
        DbgFprintf(outlogfile, PRINT_ERROR, "[-] SMB Failed to open socket. Error: %d.", GetLastError());
        return -EIO;
    }

    if (connect(fd, (struct sockaddr *)&ss, socksize) != 0 && WSAGetLastError() != WSAEWOULDBLOCK) {
        DbgFprintf(outlogfile, PRINT_ERROR, "[-] SMB Connect failed.  Error: %d.", GetLastError());
        close_wrap(fd);
        return -EIO;
    }

    *fd_out = fd;
    return 0;
}

int connect_wrap_loop(const struct addrinfo *addr_info_inst)
{
    int err = -1;
    int fd;
    for (const struct addrinfo *ai = addr_info_inst; ai != NULL; ai = ai->ai_next) {
        err = connect_wrap(ai, &fd);
        if (err == 0)
            return fd;        
    }

    return err;
}

int connect_to_server(struct smb_context *smb_context_inst, std::string server)
{
    size_t addr_count = 0;
    const char* port = "445";
    struct addrinfo* addr_info_inst;

    //in case it's a hostname
    int err = getaddrinfo(server.c_str(), port, NULL, &addr_info_inst);
    if (err != 0) {

        DbgFprintf(outlogfile, PRINT_ERROR, "[-] Invalid address:%s  Can not resolv into IPv4/v6.", server.c_str());
        
        switch (err) {
            case EAI_AGAIN:
                return -EAGAIN;
            case EAI_NONAME:
            case EAI_SERVICE:
            case EAI_FAIL:
                return -EIO;
            case EAI_MEMORY:
                return -ENOMEM;
            default:
                return -EINVAL;
        }
    }

    int fd = connect_wrap_loop(addr_info_inst);
    if (fd != -1) {
        smb_context_inst->fd = fd;
        send_negotiate_req(smb_context_inst);
    } 
    
    //Free buffer
    freeaddrinfo(addr_info_inst);

    return err;
}
