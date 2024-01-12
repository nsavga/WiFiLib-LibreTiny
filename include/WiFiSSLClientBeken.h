#ifdef LT_BK72XX

#ifndef WifiSSLClientBeken_H
#define WifiSSLClientBeken_H

#include "Print.h"
#include "Client.h"
#include "WiFiClient.h"
#include "IPAddress.h"
// #include "ssl_drv.h"

#include <inttypes.h>
#include <mbedtls/check_config.h>
#include <tls_config.h>

#include "mbedtls/platform.h"
#include "mbedtls/net.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"

#define DATA_LENTH 128

typedef struct
{
    int socket;
    mbedtls_ssl_context ssl_ctx;
    mbedtls_ssl_config ssl_conf;

    mbedtls_ctr_drbg_context drbg_ctx;
    mbedtls_entropy_context entropy_ctx;

    mbedtls_x509_crt ca_cert;
    mbedtls_x509_crt client_cert;
    mbedtls_pk_context client_key;

    unsigned long socket_timeout;
    unsigned long handshake_timeout;
} sslclient_context;

class WiFiSSLClientBeken : public WiFiClient
{

public:
    WiFiSSLClientBeken *next;
    WiFiSSLClientBeken();
    WiFiSSLClientBeken(int socket);
    ~WiFiSSLClientBeken();
    int connect(IPAddress ip, uint16_t port);
    int connect(IPAddress ip, uint16_t port, int32_t timeout);
    int connect(const char *host, uint16_t port);
    int connect(const char *host, uint16_t port, int32_t timeout);
    int connect(IPAddress ip, uint16_t port, const char *rootCABuff, const char *cli_cert, const char *cli_key);
    int connect(const char *host, uint16_t port, const char *rootCABuff, const char *cli_cert, const char *cli_key);
    int connect(IPAddress ip, uint16_t port, const char *pskIdent, const char *psKey);
    int connect(const char *host, uint16_t port, const char *pskIdent, const char *psKey);
    int connect(IPAddress ip, uint16_t port, const char *host, const char *CA_cert, const char *cert, const char *private_key);
    int peek();
    size_t write(uint8_t data);
    size_t write(const uint8_t *buf, size_t size);
    int available();
    int read();
    int read(uint8_t *buf, size_t size);
    void flush() {}
    void stop();
    uint8_t connected();
    int lastError(char *buf, const size_t size);
    void setInsecure();                                            // Don't validate the chain, just accept whatever is given.  VERY INSECURE!
    // void setPreSharedKey(const char *pskIdent, const char *psKey); // psKey in Hex
    void setCACert(const char *rootCA);
    // void setCertificate(const char *client_ca);
    // void setPrivateKey(const char *private_key);
    // bool loadCACert(Stream &stream, size_t size);
    // void setCACertBundle(const uint8_t *bundle);
    // bool loadCertificate(Stream &stream, size_t size);
    // bool loadPrivateKey(Stream &stream, size_t size);
    // bool verify(const char *fingerprint, const char *domain_name);
    void setHandshakeTimeout(unsigned long handshake_timeout);
    // void setAlpnProtocols(const char **alpn_protos);
    // const mbedtls_x509_crt *getPeerCertificate() { return mbedtls_ssl_get_peer_cert(&sslclient->ssl_ctx); };
    // bool getFingerprintSHA256(uint8_t sha256_result[32]) { return get_peer_fingerprint(sslclient, sha256_result); };
    int setTimeout(uint32_t seconds);
    int fd() const;

    operator bool()
    {
        return connected();
    }
    WiFiSSLClientBeken &operator=(const WiFiSSLClientBeken &other);
    bool operator==(const bool value)
    {
        return bool() == value;
    }
    bool operator!=(const bool value)
    {
        return bool() != value;
    }
    bool operator==(const WiFiSSLClientBeken &);
    bool operator!=(const WiFiSSLClientBeken &rhs)
    {
        return !this->operator==(rhs);
    };

    int socket()
    {
        return sslclient->socket = -1;
    }

private:
    char *_streamLoad(Stream &stream, size_t size);

    void ssl_init(sslclient_context *ssl_client);
    int start_ssl_client(sslclient_context *ssl_client, const IPAddress &ip, uint32_t port, const char *hostname, int timeout, const char *rootCABuff, bool useRootCABundle, const char *cli_cert, const char *cli_key, const char *pskIdent, const char *psKey, bool insecure, const char **alpn_protos);
    void stop_ssl_socket(sslclient_context *ssl_client, const char *rootCABuff, const char *cli_cert, const char *cli_key);
    int data_to_read(sslclient_context *ssl_client);
    int send_ssl_data(sslclient_context *ssl_client, const uint8_t *data, size_t len);
    int get_ssl_receive(sslclient_context *ssl_client, uint8_t *data, int length);
    // bool verify_ssl_fingerprint(sslclient_context *ssl_client, const char *fp, const char *domain_name);
    // bool verify_ssl_dn(sslclient_context *ssl_client, const char *domain_name);
    // bool get_peer_fingerprint(sslclient_context *ssl_client, uint8_t sha256[32]);
    String ipToString(const IPAddress &ip);
    int setSocketOption(int option, char* value, size_t len);
    int setSocketOption(int level, int option, const void* value, size_t len);
    // friend class WiFiServer;
    using Print::write;

protected:
    sslclient_context *sslclient;

    int _lastError = 0;
    int _peek = -1;
    int _timeout;
    bool _use_insecure;
    const char *_CA_cert;
    const char *_cert;
    const char *_private_key;
    const char *_pskIdent; // identity for PSK cipher suites
    const char *_psKey;    // key in hex for PSK cipher suites
    const char **_alpn_protos;
    bool _use_ca_bundle;
};

#endif

#endif
