#ifndef LT_BK72XX

#include "WiFi.h"

extern "C"
{
// #include "wl_definitions.h"
// #include "wl_types.h"
#include "string.h"
#include "errno.h"
    // #include "update.h"
}

#define MAX_SOCK_NUM 4

#include "WiFiClientRTL.h"
// #include "WiFiServer.h"
// #include "server_drv.h"

#ifdef __cplusplus
extern "C" {
// #include "ard_socket.h"
#include "platform_stdlib.h"


#include <lwip/netif.h>
#include <lwip/sockets.h>
#include <platform/platform_stdlib.h>
#include <platform_opts.h>

#include "lwip/netdb.h"


#undef read
#undef write
#undef recv
#undef connect

}
#endif

WiFiClientRTL::WiFiClientRTL() : _sock(MAX_SOCK_NUM)
{
    _is_connected = false;
    recvTimeout = 3000;
}

WiFiClientRTL::WiFiClientRTL(uint8_t sock)
{
    _sock = sock;
    // if ((sock >= 0) && (sock != 0xFF)) {
    if (sock != 0xFF)
    {
        _is_connected = true;
    }
    recvTimeout = 3000;
}

uint8_t WiFiClientRTL::connected()
{
    if ((_sock < 0) || (_sock == 0xFF))
    {
        _is_connected = false;
        return 0;
    }
    else
    {
        if (_is_connected)
        {
            return 1;
        }
        else
        {
            stop();
            return 0;
        }
    }
}

int WiFiClientRTL::available()
{
    int ret = 0;
    int err;

    if (!_is_connected)
    {
        return 0;
    }
    if (_sock >= 0)
    {
    try_again:
        ret = availData(_sock);
        if (ret > 0)
        {
            return 1;
        }
        else
        {
            err = getLastErrno(_sock);
            if (err == EAGAIN)
                goto try_again;
            if (err != 0)
            {
                _is_connected = false;
            }
            return 0;
        }
    }

    return 0;
}

int WiFiClientRTL::read()
{
    int ret;
    int err;
    uint8_t b[1];

    if (!available())
    {
        return -1;
    }

    ret = getData(_sock, b);
    if (ret > 0)
    {
        return b[0];
    }
    else
    {
        err = getLastErrno(_sock);
        if (err != EAGAIN)
        {
            _is_connected = false;
        }
    }

    return ret;
}

int WiFiClientRTL::read(uint8_t *buf, size_t size)
{
    uint16_t _size = size;
    int ret;
    int err;

    ret = getDataBuf(_sock, buf, _size);
    if (ret <= 0)
    {
        err = getLastErrno(_sock);
        if (err != EAGAIN)
        {
            _is_connected = false;
        }
    }
    return ret;
}

int WiFiClientRTL::recv(uint8_t *buf, size_t size)
{
    uint16_t _size = size;
    int ret;
    int err;

    ret = recvData(_sock, buf, _size);
    if (ret <= 0)
    {
        err = getLastErrno(_sock);
        if (err != EAGAIN)
        {
            _is_connected = false;
        }
    }
    return ret;
}

void WiFiClientRTL::stop()
{
    if (_sock < 0)
    {
        return;
    }
    stopSocket(_sock);
    _is_connected = false;
    _sock = -1;
}

size_t WiFiClientRTL::write(uint8_t b)
{
    return write(&b, 1);
}

size_t WiFiClientRTL::write(const uint8_t *buf, size_t size)
{
    if (_sock < 0)
    {
        setWriteError();
        return 0;
    }
    if (size == 0)
    {
        setWriteError();
        return 0;
    }

    if (!sendData(_sock, buf, size))
    {
        setWriteError();
        _is_connected = false;
        return 0;
    }

    return size;
}

WiFiClientRTL::operator bool()
{
    return _sock >= 0;
}

int WiFiClientRTL::connect(const char *host, uint16_t port)
{
    IPAddress remote_addr;
    IPv6Address remote_addr_v6;

    if (WiFi.hostByName(host, remote_addr))
    {
        return connect(remote_addr, port);
    }
    return 0;
}

int WiFiClientRTL::connect(const char *host, uint16_t port, int32_t connectTimeOut)
{
    _timeout = connectTimeOut;
    return connect(host, port);
}

int WiFiClientRTL::connect(IPAddress ip, uint16_t port)
{
    _is_connected = false;
    _sock = startClient(ip, port);
    // whether sock is connected
    if (_sock < 0)
    {
        _is_connected = false;
        return 0;
    }
    else
    {
        _is_connected = true;
        setSockRecvTimeout(_sock, recvTimeout);
    }
    return 1;
}

int WiFiClientRTL::peek() {
    uint8_t b;
    if (!available()) {
        return -1;
    }
    getData(_sock, &b, 1);

    return b;
}

void WiFiClientRTL::flush() {
    while (available()) {
        read();
    }
}

// extend API from RTK

int WiFiClientRTL::setRecvTimeout(int timeout) {
    if (connected()) {
        recvTimeout = timeout;
        setSockRecvTimeout(_sock, recvTimeout);
    }

    return 0;
}

int WiFiClientRTL::read(char *buf, size_t size) {
    read(((uint8_t *)buf), size);

    return 0;
}




int WiFiClientRTL::startClient(uint32_t ipAddress, uint16_t port, uint8_t protMode) {
    printf("\n\r[INFO]server_drv.cpp:  start_client");
    int sock;

    sock = start_client(ipAddress, port, protMode);

    return sock;
}

int WiFiClientRTL::getAvailable(int sock) {
    return get_available(sock);
}


int WiFiClientRTL::availData(int sock) {
    int ret;
    uint8_t c;

    if (sock < 0) {
        return 0;
    }

    if (_available) {
        return 1;
    } else {
        ret = get_receive(sock, &c, 1, 1, &_peer_addr, &_peer_port);
        if (ret == 1) {
            _available = true;
            return 1;
        } else {
            return ret;
        }
    }
}

bool WiFiClientRTL::recvData(int sock, uint8_t *_data, uint16_t _dataLen) {
    int ret;
    _available = false;

    ret = recv_data(sock, _data, _dataLen, 0);

    return ret;
}

bool WiFiClientRTL::getData(int sock, uint8_t *data, uint8_t peek) {
    int ret = 0;
    int flag = 0;

    if (peek) {
        flag |= 1;
    } else {
        _available = false;
    }

    ret = get_receive(sock, data, 1, flag, &_peer_addr, &_peer_port);

    if (ret == 1) {
        return true;
    }

    return false;
}


int WiFiClientRTL::getDataBuf(int sock, uint8_t *_data, uint16_t _dataLen) {
    int ret;
    _available = false;

    ret = get_receive(sock, _data, _dataLen, 0, &_peer_addr, &_peer_port);

    return ret;
}

int WiFiClientRTL::getLastErrno(int sock) {
    return get_sock_errno(sock);
}

void WiFiClientRTL::stopSocket(int sock) {
    close_socket(sock);
    _available = false;
}


bool WiFiClientRTL::sendData(int sock, const uint8_t *data, uint16_t len) {
    //printf("[info] server_drv.cpp sendData()");

    int ret;
    int flag = 0;

    if (sock < 0) {
        return false;
    }

    ret = send_data(sock, data, len, flag);
    if (ret <= 0) {
        return false;
    }
    return true;
}


bool WiFiClientRTL::sendtoData(int sock, const uint8_t *data, uint16_t len, uint32_t peer_ip, uint16_t peer_port) {
    int ret;

    if (sock < 0) {
        return false;
    }
    
    ret = sendto_data(sock, data, len, peer_ip, peer_port);

    if (ret == 0) {
        return false;
    }

    return true;
}

void WiFiClientRTL::getRemoteData(int sock, uint32_t *ip, uint16_t *port) {
    sock = sock;
    *ip = _peer_addr;
    *port = _peer_port;
}

int WiFiClientRTL::setSockRecvTimeout(int sock, int timeout) {
    return set_sock_recv_timeout(sock, timeout);
}










int WiFiClientRTL::start_client(uint32_t ipAddress, uint16_t port, uint8_t protMode)
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
        if (lwip_connect(_sock, ((struct sockaddr *)&serv_addr), sizeof(serv_addr)) == 0)
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

int WiFiClientRTL::get_sock_errno(int sock)
{
    int so_error;
    socklen_t len = sizeof(so_error);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
    return so_error;
}

int WiFiClientRTL::set_sock_recv_timeout(int sock, int timeout)
{
    return lwip_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
}

void WiFiClientRTL::close_socket(int sock)
{
    lwip_close(sock);
}

// TCP
int WiFiClientRTL::sock_listen(int sock, int max)
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

int WiFiClientRTL::get_available(int sock)
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

int WiFiClientRTL::recv_data(int sock, const uint8_t *data, uint16_t len, int flag)
{
    int ret;

    ret = lwip_recv(sock, (void *)data, len, flag);

    return ret;
}

int WiFiClientRTL::send_data(int sock, const uint8_t *data, uint16_t len, int flag)
{
    int ret;
    // LT_IM(SSL, "[info] ard_socket.c send_data()\r\n");
    ret = lwip_send(sock, data, len, flag);

    return ret;
}

int WiFiClientRTL::get_receive(int sock, uint8_t *data, int length, int flag, uint32_t *peer_addr, uint16_t *peer_port)
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

int WiFiClientRTL::sendto_data(int sock, const uint8_t *data, uint16_t len, uint32_t peer_ip, uint16_t peer_port)
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


#endif

