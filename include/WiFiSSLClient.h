#ifndef WifiSSLClient_H
#define WifiSSLClient_H

#include "Print.h"
#include "Client.h"
#include "WiFiClient.h"
#include "IPAddress.h"
#include "ssl_drv.h"


class WiFiSSLClient : public WiFiClient
{

public:
    WiFiSSLClient();
    WiFiSSLClient(uint8_t sock);
    ~WiFiSSLClient();

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

    void setRootCA(unsigned char *rootCA);
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
    SSLDrv ssldrv;

    unsigned char *_rootCABuff;
    unsigned char *_cli_cert;
    unsigned char *_cli_key;
    unsigned char *_psKey;
    unsigned char *_pskIdent;
    char *_sni_hostname;
};

#endif
