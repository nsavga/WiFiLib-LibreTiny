#ifndef LT_BK72XX

#ifndef WiFiSSLClientRTL_H
#define WiFiSSLClientRTL_H

#include "Print.h"
#include "Client.h"
#include "WiFiClient.h"
#include "IPAddress.h"

#include <inttypes.h>

#define DATA_LENTH 128

struct mbedtls_ssl_context;
struct mbedtls_ssl_config;

typedef struct
{
    int socket;
    int recvTimeout;
    mbedtls_ssl_context *ssl;
    mbedtls_ssl_config *conf;
} sslclient_context;

class WiFiSSLClientRTL : public WiFiClient
{

public:
    WiFiSSLClientRTL();
    WiFiSSLClientRTL(uint8_t sock);
    ~WiFiSSLClientRTL();

    uint8_t status();
    virtual int connect(IPAddress ip, uint16_t port);
    virtual int connect(const char *host, uint16_t port);
    virtual int connect(const char *host, uint16_t port, int32_t connectTimeOut);
    virtual size_t write(uint8_t);
    virtual size_t write(const uint8_t *buf, size_t size);
    virtual int available();
    virtual int read();
    virtual int read(uint8_t *buf, size_t size);
    virtual int peek();
    virtual void flush();
    virtual void stop();
    virtual uint8_t connected();
    virtual operator bool();

    void setCACert(const char *rootCA);
    void setClientCertificate(unsigned char *client_ca, unsigned char *private_key);
    void setPreSharedKey(unsigned char *pskIdent, unsigned char *psKey); // psKey expressed as hexadecimal string

    int connect(const char *host, uint16_t port, unsigned char *rootCABuff, unsigned char *cli_cert, unsigned char *cli_key);
    int connect(IPAddress ip, uint16_t port, unsigned char *rootCABuff, unsigned char *cli_cert, unsigned char *cli_key);
    int connect(const char *host, uint16_t port, unsigned char *pskIdent, unsigned char *psKey);
    int connect(IPAddress ip, uint16_t port, unsigned char *pskIdent, unsigned char *psKey);

    using Print::write;
    int setRecvTimeout(int timeoutSeconds);

private:
    int _sock;
    bool _is_connected;
    sslclient_context sslclient;

    // void setRootCA(unsigned char *rootCA);

    unsigned char *_rootCABuff;
    unsigned char *_cli_cert;
    unsigned char *_cli_key;
    unsigned char *_psKey;
    unsigned char *_pskIdent;
    char *_sni_hostname;

    bool _available;
    uint8_t c[1];
    int startClient(sslclient_context *ssl_client, uint32_t ipAddress, uint32_t port, unsigned char *rootCABuff, unsigned char *cli_cert, unsigned char *cli_key, unsigned char *pskIdent, unsigned char *psKey, char *SNI_hostname);
    void stopClient(sslclient_context *ssl_client);
    bool getData(sslclient_context *ssl_client, uint8_t *data, uint8_t peek = 0);
    int getDataBuf(sslclient_context *ssl_client, uint8_t *_data, uint16_t _dataLen);
    bool sendData(sslclient_context *ssl_client, const uint8_t *data, uint16_t len);
    uint16_t availData(sslclient_context *ssl_client);
    sslclient_context *init(void);
    int getLastErrno(sslclient_context *ssl_client);

    int setSockRecvTimeout(int sock, int timeout);

    //

    int start_ssl_client(sslclient_context *ssl_client, uint32_t ipAddress, uint32_t port, unsigned char *rootCABuff, unsigned char *cli_cert, unsigned char *cli_key, unsigned char *pskIdent, unsigned char *psKey, char *SNI_hostname);

    void stop_ssl_socket(sslclient_context *ssl_client);

    int send_ssl_data(sslclient_context *ssl_client, const uint8_t *data, uint16_t len);

    int get_ssl_receive(sslclient_context *ssl_client, uint8_t *data, int length, int flag);

    int get_ssl_sock_errno(sslclient_context *ssl_client);

    int get_ssl_bytes_avail(sslclient_context *ssl_client);
};

#endif

#endif
