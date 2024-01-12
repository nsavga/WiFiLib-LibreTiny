#include "ard_socket.h"

#include <lwip/netif.h>
#include <lwip/sockets.h>
#include <platform/platform_stdlib.h>
#include <platform_opts.h>

#include "lwip/netdb.h"


#define MAX_RECV_SIZE 1500
#define MAX_SEND_SIZE 256
#define UDP_SERVER_PORT 5002
#define TCP_SERVER_PORT 5003



int start_client(uint32_t ipAddress, uint16_t port, uint8_t protMode)
{
    int enable = 1;
    int timeout;
    int _sock;

    // create socket
    if (protMode == 0)
    { // TCP
        _sock = lwip_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    }
    else
    {
        _sock = lwip_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    }
    if (_sock < 0)
    {
        LT_IM(SSL, "\n\r[ERROR] Create socket failed\n");
        return -1;
    }
    LT_IM(SSL, "\n\r[INFO] Create socket successfully\n");

    // initialize structure dest
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = ipAddress;
    serv_addr.sin_port = htons(port);

    // Connecting to server
    if (protMode == 0)
    { // TCP MODE
        if (connect(_sock, ((struct sockaddr *)&serv_addr), sizeof(serv_addr)) == 0)
        {
            LT_IM(SSL, "\r\n[INFO] Connect to Server successfully!\r\n");
            timeout = 3000;
            lwip_setsockopt(_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            timeout = 30000;
            lwip_setsockopt(_sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
            lwip_setsockopt(_sock, IPPROTO_TCP, TCP_NODELAY, &enable, sizeof(enable));
            lwip_setsockopt(_sock, SOL_SOCKET, SO_KEEPALIVE, &enable, sizeof(enable));
            return _sock;
        }
        else
        {
            LT_IM(SSL, "\n\r[ERROR] Connect to server failed\n");
            close_socket(_sock);
            return -1;
        }
    }
    else
    {
        // LT_IM(SSL, "\r\nUdp client setup Server's information successful!\r\n");
    }
    return _sock;
}

int get_sock_errno(int sock)
{
    int so_error;
    socklen_t len = sizeof(so_error);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
    return so_error;
}

int set_sock_recv_timeout(int sock, int timeout)
{
    return lwip_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
}

void close_socket(int sock)
{
    lwip_close(sock);
}

// TCP
int sock_listen(int sock, int max)
{
    if (listen(sock, max) < 0)
    {
        // LT_IM(SSL, "\r\nERROR on listening\r\n");
        LT_IM(SSL, "\n\r[ERROR] Listen socket failed, socket closed\n");
        close_socket(sock);
        return -1;
    }
    LT_IM(SSL, "\n\r[INFO] Listen socket successfully\n");
    return 0;
}

int get_available(int sock)
{
    int enable = 1;
    int timeout;
    int client_fd;
    int err;
    struct sockaddr_in cli_addr;

    socklen_t client = sizeof(cli_addr);

    do
    {
        client_fd = lwip_accept(sock, ((struct sockaddr *)&cli_addr), &client);
        if (client_fd < 0)
        {
            err = get_sock_errno(sock);
            if (err != EAGAIN)
            {
                break;
            }
        }
    } while (client_fd < 0);

    if (client_fd < 0)
    {
        LT_IM(SSL, "\n\r[ERROR] Accept connection failed\n");
        return -1;
    }
    else
    {
        timeout = 3000;
        lwip_setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        timeout = 30000;
        lwip_setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        lwip_setsockopt(client_fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));
        lwip_setsockopt(client_fd, SOL_SOCKET, SO_KEEPALIVE, &enable, sizeof(enable));
        LT_IM(SSL, "\n\r[INFO] Accept connection successfully\n");
        LT_IM(SSL, "\r\nA client connected to this server :\r\n[PORT]: %d\r\n[IP]:%s\r\n\r\n", ntohs(cli_addr.sin_port), inet_ntoa(cli_addr.sin_addr.s_addr));
        return client_fd;
    }
}

int recv_data(int sock, const uint8_t *data, uint16_t len, int flag)
{
    int ret;

    ret = lwip_recv(sock, (void *)data, len, flag);

    return ret;
}

int send_data(int sock, const uint8_t *data, uint16_t len, int flag)
{
    int ret;
    // LT_IM(SSL, "[info] ard_socket.c send_data()\r\n");
    ret = lwip_send(sock, data, len, flag);

    return ret;
}

int get_receive(int sock, uint8_t *data, int length, int flag, uint32_t *peer_addr, uint16_t *peer_port)
{
    int ret = 0;
    struct sockaddr from;
    socklen_t fromlen;

    uint8_t backup_recvtimeout = 0;
    int backup_recv_timeout, recv_timeout;
    socklen_t len;

    if (flag & 0x01)
    {
        // for MSG_PEEK, we try to peek packets by changing receiving timeout to 10ms
        ret = lwip_getsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &backup_recv_timeout, &len);
        if (ret >= 0)
        {
            recv_timeout = 10;
            ret = lwip_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &recv_timeout, sizeof(recv_timeout));
            if (ret >= 0)
            {
                backup_recvtimeout = 1;
            }
        }
    }
    ret = lwip_recvfrom(sock, data, length, flag, &from, &fromlen);

    if (ret >= 0)
    {
        if (peer_addr != NULL)
        {
            *peer_addr = ((struct sockaddr_in *)&from)->sin_addr.s_addr;
        }
        if (peer_port != NULL)
        {
            *peer_port = ntohs(((struct sockaddr_in *)&from)->sin_port);
        }
    }

    if ((flag & 0x01) && (backup_recvtimeout == 1))
    {
        // restore receiving timeout
        lwip_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &backup_recv_timeout, sizeof(recv_timeout));
    }

    return ret;
}

int sendto_data(int sock, const uint8_t *data, uint16_t len, uint32_t peer_ip, uint16_t peer_port)
{
    int ret;
    struct sockaddr_in peer_addr;

    memset(&peer_addr, 0, sizeof(peer_addr));
    peer_addr.sin_family = AF_INET;
    peer_addr.sin_addr.s_addr = peer_ip;
    peer_addr.sin_port = htons(peer_port);

    ret = lwip_sendto(sock, data, len, 0, ((struct sockaddr *)&peer_addr), sizeof(struct sockaddr_in));

    return ret;
}
