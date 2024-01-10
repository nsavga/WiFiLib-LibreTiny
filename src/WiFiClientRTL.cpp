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
#include "server_drv.h"

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
        ret = clientdrv.availData(_sock);
        if (ret > 0)
        {
            return 1;
        }
        else
        {
            err = clientdrv.getLastErrno(_sock);
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

    ret = clientdrv.getData(_sock, b);
    if (ret > 0)
    {
        return b[0];
    }
    else
    {
        err = clientdrv.getLastErrno(_sock);
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

    ret = clientdrv.getDataBuf(_sock, buf, _size);
    if (ret <= 0)
    {
        err = clientdrv.getLastErrno(_sock);
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

    ret = clientdrv.recvData(_sock, buf, _size);
    if (ret <= 0)
    {
        err = clientdrv.getLastErrno(_sock);
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
    clientdrv.stopSocket(_sock);
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

    if (!clientdrv.sendData(_sock, buf, size))
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
    _sock = clientdrv.startClient(ip, port);
    // whether sock is connected
    if (_sock < 0)
    {
        _is_connected = false;
        return 0;
    }
    else
    {
        _is_connected = true;
        clientdrv.setSockRecvTimeout(_sock, recvTimeout);
    }
    return 1;
}

int WiFiClientRTL::peek() {
    uint8_t b;
    if (!available()) {
        return -1;
    }
    clientdrv.getData(_sock, &b, 1);

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
        clientdrv.setSockRecvTimeout(_sock, recvTimeout);
    }

    return 0;
}

int WiFiClientRTL::read(char *buf, size_t size) {
    read(((uint8_t *)buf), size);

    return 0;
}
