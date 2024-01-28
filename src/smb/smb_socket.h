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


