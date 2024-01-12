#ifndef LT_BK72XX

#ifndef WifiClientRTL_h
#define WifiClientRTL_h

#include "Print.h"
#include "WiFiClient.h"
#include "IPAddress.h"
// #include "server_drv.h"
#include <stdint.h>

typedef enum eProtMode
{
    TCP_MODE,
    UDP_MODE
} tProtMode;

#define DATA_LENTH 128

class WiFiClientRTL : public WiFiClient
{
public:
    WiFiClientRTL();
    WiFiClientRTL(uint8_t sock);

    uint8_t status();
    virtual uint8_t connected();
    virtual int available();
    virtual int read();
    virtual int read(uint8_t *buf, size_t size);
    virtual int recv(uint8_t *buf, size_t size);
    virtual void stop();
    virtual size_t write(uint8_t);
    virtual size_t write(const uint8_t *buf, size_t size);
    virtual operator bool();
    virtual int connect(const char *host, uint16_t port);
    virtual int connect(IPAddress ip, uint16_t port);
    virtual int connect(const char *host, uint16_t port, int32_t connectTimeOut);
    virtual int peek();
    virtual void flush();
    // extend API from RTK
    int setRecvTimeout(int timeout);
    int read(char *buf, size_t size);

    // friend class WiFiServer;
    using Print::write;

private:
    int _sock;
    // ServerDrv clientdrv;
    bool _is_connected;
    uint8_t data[DATA_LENTH];

    int recvTimeout;

    bool _available;
    uint32_t _peer_addr;
    uint16_t _peer_port;

    int startClient(uint32_t ipAddress, uint16_t port, uint8_t protMode = TCP_MODE);

    int getAvailable(int sock);

    int availData(int sock);

    bool recvData(int sock, uint8_t *_data, uint16_t _dataLen);

    bool getData(int sock, uint8_t *data, uint8_t peek = 0);

    int getDataBuf(int sock, uint8_t *_data, uint16_t _dataLen);

    int getLastErrno(int sock);

    void stopSocket(int sock);

    bool sendData(int sock, const uint8_t *data, uint16_t len);

    bool sendtoData(int sock, const uint8_t *data, uint16_t len, uint32_t peer_ip, uint16_t peer_port);

    void getRemoteData(int sock, uint32_t *ip, uint16_t *port);

    int setSockRecvTimeout(int sock, int timeout);

    //

    int start_client(uint32_t ipAddress, uint16_t port, uint8_t protMode);

    int get_sock_errno(int sock);

    int set_sock_recv_timeout(int sock, int timeout);

    void close_socket(int sock);

    // TCP
    int sock_listen(int sock, int max);

    int get_available(int sock);

    int recv_data(int sock, const uint8_t *data, uint16_t len, int flag);

    int send_data(int sock, const uint8_t *data, uint16_t len, int flag);
    // UDP
    int get_receive(int sock, uint8_t *data, int length, int flag, uint32_t *peer_addr, uint16_t *peer_port);

    int sendto_data(int sock, const uint8_t *data, uint16_t len, uint32_t peer_ip, uint16_t peer_port);
};

#endif

#endif
