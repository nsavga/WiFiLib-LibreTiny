#ifdef LT_BK72XX

#include "Arduino.h"
#include "WiFi.h"
#include "WiFiSSLClientBeken.h"

extern "C"
{

#include "string.h"
#include "errno.h"

#include <mbedtls/check_config.h>

#include "mbedtls/certs.h"
#include <sockets.h>
#include <lwip/netif.h>
#include <mbedtls/platform.h>
#include <mbedtls/ssl.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/error.h>
#include <mbedtls/debug.h>
#include <lwip/sockets.h>
#include <lwip/netdb.h>
#include <errno.h>

#undef read
#undef write
#undef recv
#undef connect
}

static int _handle_error(int err, const char *function, int line)
{
    if (err == -30848)
    {
        return err;
    }
#ifdef MBEDTLS_ERROR_C
    char error_buf[100];
    mbedtls_strerror(err, error_buf, 100);
    LT_IM(SSL, "[%s():%d]: (%d) %s", function, line, err, error_buf);
#else
    LT_IM(SSL, "[%s():%d]: code %d", function, line, err);
#endif
    return err;
}

#define handle_error(e) _handle_error(e, __FUNCTION__, __LINE__)

WiFiSSLClientBeken::WiFiSSLClientBeken()
{
    _connected = false;
    _timeout = 30000; // Same default as ssl_client

    sslclient = new sslclient_context;
    ssl_init(sslclient);
    sslclient->socket = -1;
    sslclient->handshake_timeout = 120000;
    _use_insecure = false;
    _CA_cert = NULL;
    _cert = NULL;
    _private_key = NULL;
    _pskIdent = NULL;
    _psKey = NULL;
    next = NULL;
    _alpn_protos = NULL;
    _use_ca_bundle = false;
}

WiFiSSLClientBeken::WiFiSSLClientBeken(int sock)
{
    _connected = false;
    _timeout = 30000; // Same default as ssl_client

    sslclient = new sslclient_context;
    ssl_init(sslclient);
    sslclient->socket = sock;
    sslclient->handshake_timeout = 120000;

    if (sock >= 0)
    {
        _connected = true;
    }

    _CA_cert = NULL;
    _cert = NULL;
    _private_key = NULL;
    _pskIdent = NULL;
    _psKey = NULL;
    next = NULL;
    _alpn_protos = NULL;
}

WiFiSSLClientBeken::~WiFiSSLClientBeken()
{
    stop();
    delete sslclient;
}

WiFiSSLClientBeken &WiFiSSLClientBeken::operator=(const WiFiSSLClientBeken &other)
{
    stop();
    sslclient->socket = other.sslclient->socket;
    _connected = other._connected;
    return *this;
}

void WiFiSSLClientBeken::stop()
{
    if (sslclient->socket >= 0)
    {
        close(sslclient->socket);
        sslclient->socket = -1;
        _connected = false;
        _peek = -1;
    }
    stop_ssl_socket(sslclient, _CA_cert, _cert, _private_key);
}

int WiFiSSLClientBeken::connect(IPAddress ip, uint16_t port)
{
    if (_pskIdent && _psKey)
        return connect(ip, port, _pskIdent, _psKey);
    return connect(ip, port, _CA_cert, _cert, _private_key);
}

int WiFiSSLClientBeken::connect(IPAddress ip, uint16_t port, int32_t timeout)
{
    _timeout = timeout;
    return connect(ip, port);
}

int WiFiSSLClientBeken::connect(const char *host, uint16_t port)
{
    if (_pskIdent && _psKey)
        return connect(host, port, _pskIdent, _psKey);
    return connect(host, port, _CA_cert, _cert, _private_key);
}

int WiFiSSLClientBeken::connect(const char *host, uint16_t port, int32_t timeout)
{
    _timeout = timeout;
    return connect(host, port);
}

int WiFiSSLClientBeken::connect(IPAddress ip, uint16_t port, const char *CA_cert, const char *cert, const char *private_key)
{
    return connect(ip, port, NULL, CA_cert, cert, private_key);
}

int WiFiSSLClientBeken::connect(const char *host, uint16_t port, const char *CA_cert, const char *cert, const char *private_key)
{
    IPAddress address;
    if (!WiFi.hostByName(host, address))
        return 0;

    return connect(address, port, host, CA_cert, cert, private_key);
}

int WiFiSSLClientBeken::connect(IPAddress ip, uint16_t port, const char *host, const char *CA_cert, const char *cert, const char *private_key)
{
    int ret = start_ssl_client(sslclient, ip, port, host, _timeout, CA_cert, _use_ca_bundle, cert, private_key, NULL, NULL, _use_insecure, _alpn_protos);
    _lastError = ret;
    if (ret < 0)
    {
        LT_EM(SSL, "start_ssl_client: %d", ret);
        stop();
        return 0;
    }
    _connected = true;
    return 1;
}

String WiFiSSLClientBeken::ipToString(const IPAddress &ip)
{
    char szRet[16];
    sprintf(szRet, "%hhu.%hhu.%hhu.%hhu", ip[0], ip[1], ip[2], ip[3]);
    return String(szRet);
}

int WiFiSSLClientBeken::connect(IPAddress ip, uint16_t port, const char *pskIdent, const char *psKey)
{
    return connect(ipToString(ip).c_str(), port, pskIdent, psKey);
}

int WiFiSSLClientBeken::connect(const char *host, uint16_t port, const char *pskIdent, const char *psKey)
{
    LT_IM(SSL, "start_ssl_client with PSK");

    IPAddress address;
    if (!WiFi.hostByName(host, address))
        return 0;

    int ret = start_ssl_client(sslclient, address, port, host, _timeout, NULL, false, NULL, NULL, pskIdent, psKey, _use_insecure, _alpn_protos);
    _lastError = ret;
    if (ret < 0)
    {
        LT_EM(SSL, "start_ssl_client: %d", ret);
        stop();
        return 0;
    }
    _connected = true;
    return 1;
}

int WiFiSSLClientBeken::peek()
{
    if (_peek >= 0)
    {
        return _peek;
    }
    _peek = timedRead();
    return _peek;
}

size_t WiFiSSLClientBeken::write(uint8_t data)
{
    return write(&data, 1);
}

int WiFiSSLClientBeken::read()
{
    uint8_t data = -1;
    int res = read(&data, 1);
    if (res < 0)
    {
        return res;
    }
    return data;
}

size_t WiFiSSLClientBeken::write(const uint8_t *buf, size_t size)
{
    if (!_connected)
    {
        return 0;
    }
    int res = send_ssl_data(sslclient, buf, size);
    if (res < 0)
    {
        stop();
        res = 0;
    }
    return res;
}

int WiFiSSLClientBeken::read(uint8_t *buf, size_t size)
{
    int peeked = 0;
    int avail = available();
    if ((!buf && size) || avail <= 0)
    {
        return -1;
    }
    if (!size)
    {
        return 0;
    }
    if (_peek >= 0)
    {
        buf[0] = _peek;
        _peek = -1;
        size--;
        avail--;
        if (!size || !avail)
        {
            return 1;
        }
        buf++;
        peeked = 1;
    }

    int res = get_ssl_receive(sslclient, buf, size);
    if (res < 0)
    {
        stop();
        return peeked ? peeked : res;
    }
    return res + peeked;
}

int WiFiSSLClientBeken::available()
{
    int peeked = (_peek >= 0);
    if (!_connected)
    {
        return peeked;
    }
    int res = data_to_read(sslclient);
    if (res < 0)
    {
        stop();
        return peeked ? peeked : res;
    }
    
    return res + peeked;
}

uint8_t WiFiSSLClientBeken::connected()
{
    uint8_t dummy = 0;
    read(&dummy, 0);

    return _connected;
}

void WiFiSSLClientBeken::setInsecure()
{
    _CA_cert = NULL;
    _cert = NULL;
    _private_key = NULL;
    _pskIdent = NULL;
    _psKey = NULL;
    _use_insecure = true;
}

void WiFiSSLClientBeken::setCACert(const char *rootCA)
{
    _CA_cert = rootCA;
    _use_insecure = false;
}

//  void WiFiSSLClientBeken::setCACertBundle(const uint8_t * bundle)
//  {
//     if (bundle != NULL)
//     {
//         arduino_esp_crt_bundle_set(bundle);
//         _use_ca_bundle = true;
//     } else {
//         arduino_esp_crt_bundle_detach(NULL);
//         _use_ca_bundle = false;
//     }
//  }

// void WiFiSSLClientBeken::setCertificate (const char *client_ca)
// {
//     _cert = client_ca;
// }

// void WiFiSSLClientBeken::setPrivateKey (const char *private_key)
// {
//     _private_key = private_key;
// }

// void WiFiSSLClientBeken::setPreSharedKey(const char *pskIdent, const char *psKey) {
//     _pskIdent = pskIdent;
//     _psKey = psKey;
// }

// bool WiFiSSLClientBeken::verify(const char* fp, const char* domain_name)
// {
//     if (!sslclient)
//         return false;

//     return verify_ssl_fingerprint(sslclient, fp, domain_name);
// }

char *WiFiSSLClientBeken::_streamLoad(Stream &stream, size_t size)
{
    char *dest = (char *)malloc(size + 1);
    if (!dest)
    {
        return nullptr;
    }
    if (size != stream.readBytes(dest, size))
    {
        free(dest);
        dest = nullptr;
        return nullptr;
    }
    dest[size] = '\0';
    return dest;
}

// bool WiFiSSLClientBeken::loadCACert(Stream& stream, size_t size) {
//   if (_CA_cert != NULL) free(const_cast<char*>(_CA_cert));
//   char *dest = _streamLoad(stream, size);
//   bool ret = false;
//   if (dest) {
//     setCACert(dest);
//     ret = true;
//   }
//   return ret;
// }

// bool WiFiSSLClientBeken::loadCertificate(Stream& stream, size_t size) {
//   if (_cert != NULL) free(const_cast<char*>(_cert));
//   char *dest = _streamLoad(stream, size);
//   bool ret = false;
//   if (dest) {
//     setCertificate(dest);
//     ret = true;
//   }
//   return ret;
// }

// bool WiFiSSLClientBeken::loadPrivateKey(Stream& stream, size_t size) {
//   if (_private_key != NULL) free(const_cast<char*>(_private_key));
//   char *dest = _streamLoad(stream, size);
//   bool ret = false;
//   if (dest) {
//     setPrivateKey(dest);
//     ret = true;
//   }
//   return ret;
// }

int WiFiSSLClientBeken::lastError(char *buf, const size_t size)
{
    if (!_lastError)
    {
        return 0;
    }
    mbedtls_strerror(_lastError, buf, size);
    return _lastError;
}

void WiFiSSLClientBeken::setHandshakeTimeout(unsigned long handshake_timeout)
{
    sslclient->handshake_timeout = handshake_timeout * 1000;
}

int WiFiSSLClientBeken::setSocketOption(int option, char *value, size_t len)
{
    return setSocketOption(SOL_SOCKET, option, (const void *)value, len);
}

int WiFiSSLClientBeken::setSocketOption(int level, int option, const void *value, size_t len)
{
    int res = lwip_setsockopt(fd(), level, option, value, len);
    if (res < 0)
    {
        LT_EM(SSL, "fail on %d, errno: %d, \"%s\"", fd(), errno, strerror(errno));
    }
    return res;
}

// void WiFiSSLClientBeken::setAlpnProtocols(const char **alpn_protos)
// {
//     _alpn_protos = alpn_protos;
// }

int WiFiSSLClientBeken::setTimeout(uint32_t seconds)
{
    _timeout = seconds * 1000;
    if (sslclient->socket >= 0)
    {
        struct timeval tv;
        tv.tv_sec = seconds;
        tv.tv_usec = 0;
        if (setSocketOption(SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval)) < 0)
        {
            return -1;
        }
        return setSocketOption(SO_SNDTIMEO, (char *)&tv, sizeof(struct timeval));
    }
    else
    {
        return 0;
    }
}

int WiFiSSLClientBeken::fd() const
{
    return sslclient->socket;
}

void WiFiSSLClientBeken::ssl_init(sslclient_context *ssl_client)
{
    // reset embedded pointers to zero
    memset(ssl_client, 0, sizeof(sslclient_context));
    mbedtls_ssl_init(&ssl_client->ssl_ctx);
    mbedtls_ssl_config_init(&ssl_client->ssl_conf);
    mbedtls_ctr_drbg_init(&ssl_client->drbg_ctx);
}

int WiFiSSLClientBeken::start_ssl_client(sslclient_context *ssl_client, const IPAddress &ip, uint32_t port, const char *hostname, int timeout, const char *rootCABuff, bool useRootCABundle, const char *cli_cert, const char *cli_key, const char *pskIdent, const char *psKey, bool insecure, const char **alpn_protos)
{
    char buf[512];
    int ret, flags;
    int enable = 1;
    LT_IM(SSL, "Free internal heap before TLS %u", ESP.getFreeHeap());

    if (rootCABuff == NULL && pskIdent == NULL && psKey == NULL && !insecure && !useRootCABundle)
    {
        return -1;
    }

    LT_IM(SSL, "Starting socket");
    ssl_client->socket = -1;

    ssl_client->socket = lwip_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ssl_client->socket < 0)
    {
        LT_EM(SSL, "ERROR opening socket");
        return ssl_client->socket;
    }

    int hede = -1;

    hede = fcntl(ssl_client->socket, F_SETFL, fcntl(ssl_client->socket, F_GETFL, 0) | O_NONBLOCK);
    LT_IM(SSL,"O_NONBLOCK = %d\n", hede);

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = ip;
    serv_addr.sin_port = htons(port);

    if (timeout <= 0)
    {
        timeout = 30000; // Milli seconds.
    }

    ssl_client->socket_timeout = timeout;

    fd_set fdset;
    struct timeval tv;
    FD_ZERO(&fdset);
    FD_SET(ssl_client->socket, &fdset);
    tv.tv_sec = timeout / 1000;
    tv.tv_usec = (timeout % 1000) * 1000;

    int res = lwip_connect(ssl_client->socket, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    if (res < 0 && errno != EINPROGRESS)
    {
        LT_EM(SSL, "connect on fd %d, errno: %d, \"%s\"", ssl_client->socket, errno, strerror(errno));
        lwip_close(ssl_client->socket);
        ssl_client->socket = -1;
        return -1;
    }

    res = select(ssl_client->socket + 1, nullptr, &fdset, nullptr, timeout < 0 ? nullptr : &tv);
    if (res < 0)
    {
        LT_EM(SSL, "select on fd %d, errno: %d, \"%s\"", ssl_client->socket, errno, strerror(errno));
        lwip_close(ssl_client->socket);
        ssl_client->socket = -1;
        return -1;
    }
    else if (res == 0)
    {
        LT_IM(SSL, "select returned due to timeout %d ms for fd %d", timeout, ssl_client->socket);
        lwip_close(ssl_client->socket);
        ssl_client->socket = -1;
        return -1;
    }
    else
    {
        int sockerr;
        socklen_t len = (socklen_t)sizeof(int);
        res = getsockopt(ssl_client->socket, SOL_SOCKET, SO_ERROR, &sockerr, &len);

        if (res < 0)
        {
            LT_EM(SSL, "getsockopt on fd %d, errno: %d, \"%s\"", ssl_client->socket, errno, strerror(errno));
            lwip_close(ssl_client->socket);
            ssl_client->socket = -1;
            return -1;
        }

        if (sockerr != 0)
        {
            LT_EM(SSL, "socket error on fd %d, errno: %d, \"%s\"", ssl_client->socket, sockerr, strerror(sockerr));
            lwip_close(ssl_client->socket);
            ssl_client->socket = -1;
            return -1;
        }
    }

    hede = lwip_setsockopt(ssl_client->socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    LT_IM(SSL,"SO_RCVTIMEO = %d\n", hede);
    hede = lwip_setsockopt(ssl_client->socket, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    LT_IM(SSL,"SO_SNDTIMEO = %d\n", hede);
    hede = lwip_setsockopt(ssl_client->socket, IPPROTO_TCP, TCP_NODELAY, &enable, sizeof(enable));
    LT_IM(SSL,"TCP_NODELAY = %d\n", hede);
    hede = lwip_setsockopt(ssl_client->socket, SOL_SOCKET, SO_KEEPALIVE, &enable, sizeof(enable));

    LT_IM(SSL,"SO_KEEPALIVE = %d\n", hede);

    LT_IM(SSL, "Seeding the random number generator");
    mbedtls_entropy_init(&ssl_client->entropy_ctx);

    const char *pers = "esp32-tls";

    ret = mbedtls_ctr_drbg_seed(&ssl_client->drbg_ctx, mbedtls_entropy_func,
                                &ssl_client->entropy_ctx, (const unsigned char *)pers, strlen(pers));
    if (ret < 0)
    {
        return handle_error(ret);
    }

    LT_IM(SSL, "Setting up the SSL/TLS structure...");

    if ((ret = mbedtls_ssl_config_defaults(&ssl_client->ssl_conf,
                                           MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        return handle_error(ret);
    }

    // if (alpn_protos != NULL) {
    //     LT_IM(SSL, "Setting ALPN protocols");
    //     if ((ret = mbedtls_ssl_conf_alpn_protocols(&ssl_client->ssl_conf, alpn_protos) ) != 0) {
    //         return handle_error(ret);
    //     }
    // }

    // MBEDTLS_SSL_VERIFY_REQUIRED if a CA certificate is defined on Arduino IDE and
    // MBEDTLS_SSL_VERIFY_NONE if not.

    if (insecure)
    {
        mbedtls_ssl_conf_authmode(&ssl_client->ssl_conf, MBEDTLS_SSL_VERIFY_NONE);
        LT_DM(SSL, "WARNING: Skipping SSL Verification. INSECURE!");
    }
    else if (rootCABuff != NULL)
    {
        LT_IM(SSL, "Loading CA cert");
        mbedtls_x509_crt_init(&ssl_client->ca_cert);
        mbedtls_ssl_conf_authmode(&ssl_client->ssl_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
        ret = mbedtls_x509_crt_parse(&ssl_client->ca_cert, (const unsigned char *)rootCABuff, strlen(rootCABuff) + 1);
        mbedtls_ssl_conf_ca_chain(&ssl_client->ssl_conf, &ssl_client->ca_cert, NULL);
        // mbedtls_ssl_conf_verify(&ssl_client->ssl_ctx, my_verify, NULL );
        if (ret < 0)
        {
            // free the ca_cert in the case parse failed, otherwise, the old ca_cert still in the heap memory, that lead to "out of memory" crash.
            mbedtls_x509_crt_free(&ssl_client->ca_cert);
            return handle_error(ret);
        }
    }
    else if (useRootCABundle)
    {
        // LT_IM(SSL, "Attaching root CA cert bundle");
        // ret = arduino_esp_crt_bundle_attach(&ssl_client->ssl_conf);

        // if (ret < 0) {
        //     return handle_error(ret);
        // }
    }
    else if (pskIdent != NULL && psKey != NULL)
    {
        LT_IM(SSL, "Setting up PSK");
        // convert PSK from hex to binary
        if ((strlen(psKey) & 1) != 0 || strlen(psKey) > 2 * MBEDTLS_PSK_MAX_LEN)
        {
            LT_EM(SSL, "pre-shared key not valid hex or too long");
            return -1;
        }
        unsigned char psk[MBEDTLS_PSK_MAX_LEN];
        size_t psk_len = strlen(psKey) / 2;
        for (int j = 0; j < strlen(psKey); j += 2)
        {
            char c = psKey[j];
            if (c >= '0' && c <= '9')
                c -= '0';
            else if (c >= 'A' && c <= 'F')
                c -= 'A' - 10;
            else if (c >= 'a' && c <= 'f')
                c -= 'a' - 10;
            else
                return -1;
            psk[j / 2] = c << 4;
            c = psKey[j + 1];
            if (c >= '0' && c <= '9')
                c -= '0';
            else if (c >= 'A' && c <= 'F')
                c -= 'A' - 10;
            else if (c >= 'a' && c <= 'f')
                c -= 'a' - 10;
            else
                return -1;
            psk[j / 2] |= c;
        }
        // set mbedtls config
        ret = mbedtls_ssl_conf_psk(&ssl_client->ssl_conf, psk, psk_len,
                                   (const unsigned char *)pskIdent, strlen(pskIdent));
        if (ret != 0)
        {
            LT_EM(SSL, "mbedtls_ssl_conf_psk returned %d", ret);
            return handle_error(ret);
        }
    }
    else
    {
        return -1;
    }

    if (!insecure && cli_cert != NULL && cli_key != NULL)
    {
        mbedtls_x509_crt_init(&ssl_client->client_cert);
        mbedtls_pk_init(&ssl_client->client_key);

        LT_IM(SSL, "Loading CRT cert");

        ret = mbedtls_x509_crt_parse(&ssl_client->client_cert, (const unsigned char *)cli_cert, strlen(cli_cert) + 1);
        if (ret < 0)
        {
            // free the client_cert in the case parse failed, otherwise, the old client_cert still in the heap memory, that lead to "out of memory" crash.
            mbedtls_x509_crt_free(&ssl_client->client_cert);
            return handle_error(ret);
        }

        LT_IM(SSL, "Loading private key");
        ret = mbedtls_pk_parse_key(&ssl_client->client_key, (const unsigned char *)cli_key, strlen(cli_key) + 1, NULL, 0);

        if (ret != 0)
        {
            mbedtls_x509_crt_free(&ssl_client->client_cert); // cert+key are free'd in pair
            return handle_error(ret);
        }

        mbedtls_ssl_conf_own_cert(&ssl_client->ssl_conf, &ssl_client->client_cert, &ssl_client->client_key);
    }

    LT_IM(SSL, "Setting hostname for TLS session...");

    // Hostname set here should match CN in server certificate
    if ((ret = mbedtls_ssl_set_hostname(&ssl_client->ssl_ctx, hostname != NULL ? hostname : ipToString(ip).c_str())) != 0)
    {
        return handle_error(ret);
    }

    mbedtls_ssl_conf_rng(&ssl_client->ssl_conf, mbedtls_ctr_drbg_random, &ssl_client->drbg_ctx);

    if ((ret = mbedtls_ssl_setup(&ssl_client->ssl_ctx, &ssl_client->ssl_conf)) != 0)
    {
        return handle_error(ret);
    }

    ret = mbedtls_ssl_conf_max_frag_len(&ssl_client->ssl_conf, MBEDTLS_SSL_MAX_FRAG_LEN_1024);

    mbedtls_ssl_set_bio(&ssl_client->ssl_ctx, &ssl_client->socket, mbedtls_net_send, mbedtls_net_recv, NULL);

    LT_IM(SSL, "Performing the SSL/TLS handshake...");
    unsigned long handshake_start_time = millis();
    while ((ret = mbedtls_ssl_handshake(&ssl_client->ssl_ctx)) != 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            return handle_error(ret);
        }
        if ((millis() - handshake_start_time) > ssl_client->handshake_timeout)
            return -1;
        vTaskDelay(2); // 2 ticks
    }

    if (cli_cert != NULL && cli_key != NULL)
    {
        LT_DM(SSL, "Protocol is %s Ciphersuite is %s", mbedtls_ssl_get_version(&ssl_client->ssl_ctx), mbedtls_ssl_get_ciphersuite(&ssl_client->ssl_ctx));
        if ((ret = mbedtls_ssl_get_record_expansion(&ssl_client->ssl_ctx)) >= 0)
        {
            LT_DM(SSL, "Record expansion is %d", ret);
        }
        else
        {
            LT_EM(SSL, "Record expansion is unknown (compression)");
        }
    }

    LT_IM(SSL, "Verifying peer X.509 certificate...");

    if ((flags = mbedtls_ssl_get_verify_result(&ssl_client->ssl_ctx)) != 0)
    {
        memset(buf, 0, sizeof(buf));
        mbedtls_x509_crt_verify_info(buf, sizeof(buf), "  ! ", flags);
        LT_EM(SSL, "Failed to verify peer certificate! verification info: %s", buf);
        return handle_error(ret);
    }
    else
    {
        LT_IM(SSL, "Certificate verified.");
    }

    if (rootCABuff != NULL)
    {
        mbedtls_x509_crt_free(&ssl_client->ca_cert);
    }

    if (cli_cert != NULL)
    {
        mbedtls_x509_crt_free(&ssl_client->client_cert);
    }

    if (cli_key != NULL)
    {
        mbedtls_pk_free(&ssl_client->client_key);
    }

    LT_IM(SSL, "Free internal heap after TLS %u", ESP.getFreeHeap());

    return ssl_client->socket;
}

void WiFiSSLClientBeken::stop_ssl_socket(sslclient_context *ssl_client, const char *rootCABuff, const char *cli_cert, const char *cli_key)
{
    LT_IM(SSL, "Cleaning SSL connection.");

    if (ssl_client->socket >= 0)
    {
        lwip_close(ssl_client->socket);
        ssl_client->socket = -1;
    }

    // avoid memory leak if ssl connection attempt failed
    if (ssl_client->ssl_conf.ca_chain != NULL)
    {
        mbedtls_x509_crt_free(&ssl_client->ca_cert);
    }
    if (ssl_client->ssl_conf.key_cert != NULL)
    {
        mbedtls_x509_crt_free(&ssl_client->client_cert);
        mbedtls_pk_free(&ssl_client->client_key);
    }
    mbedtls_ssl_free(&ssl_client->ssl_ctx);
    mbedtls_ssl_config_free(&ssl_client->ssl_conf);
    mbedtls_ctr_drbg_free(&ssl_client->drbg_ctx);
    mbedtls_entropy_free(&ssl_client->entropy_ctx);

    // save only interesting fields
    int handshake_timeout = ssl_client->handshake_timeout;
    int socket_timeout = ssl_client->socket_timeout;

    // reset embedded pointers to zero
    memset(ssl_client, 0, sizeof(sslclient_context));

    ssl_client->handshake_timeout = handshake_timeout;
    ssl_client->socket_timeout = socket_timeout;
}

int WiFiSSLClientBeken::data_to_read(sslclient_context *ssl_client)
{
    int ret, res;
    ret = mbedtls_ssl_read(&ssl_client->ssl_ctx, NULL, 0);
    // LT_EM(SSL, "RET: %i",ret);   //for low level debug
    res = mbedtls_ssl_get_bytes_avail(&ssl_client->ssl_ctx);
    // LT_EM(SSL, "RES: %i",res);    //for low level debug
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret < 0)
    {
        return handle_error(ret);
    }

    return res;
}

int WiFiSSLClientBeken::send_ssl_data(sslclient_context *ssl_client, const uint8_t *data, size_t len)
{
    LT_IM(SSL, "Writing HTTP request with %d bytes...", len); // for low level debug
    int ret = -1;

    unsigned long write_start_time = millis();

    while ((ret = mbedtls_ssl_write(&ssl_client->ssl_ctx, data, len)) <= 0)
    {
        if ((millis() - write_start_time) > ssl_client->socket_timeout)
        {
            LT_IM(SSL, "SSL write timed out.");
            return -1;
        }

        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret < 0)
        {
            LT_IM(SSL, "Handling error %d", ret); // for low level debug
            return handle_error(ret);
        }

        // wait for space to become available
        vTaskDelay(2);
    }

    return ret;
}

int WiFiSSLClientBeken::get_ssl_receive(sslclient_context *ssl_client, uint8_t *data, int length)
{
    // LT_DM(SSL,  "Reading HTTP response...");   //for low level debug
    int ret = -1;

    ret = mbedtls_ssl_read(&ssl_client->ssl_ctx, data, length);

    // LT_IM(SSL,  "%d bytes read", ret);   //for low level debug
    return ret;
}

static bool parseHexNibble(char pb, uint8_t *res)
{
    if (pb >= '0' && pb <= '9')
    {
        *res = (uint8_t)(pb - '0');
        return true;
    }
    else if (pb >= 'a' && pb <= 'f')
    {
        *res = (uint8_t)(pb - 'a' + 10);
        return true;
    }
    else if (pb >= 'A' && pb <= 'F')
    {
        *res = (uint8_t)(pb - 'A' + 10);
        return true;
    }
    return false;
}

// // Compare a name from certificate and domain name, return true if they match
// static bool matchName(const std::string& name, const std::string& domainName)
// {
//     size_t wildcardPos = name.find('*');
//     if (wildcardPos == std::string::npos) {
//         // Not a wildcard, expect an exact match
//         return name == domainName;
//     }

//     size_t firstDotPos = name.find('.');
//     if (wildcardPos > firstDotPos) {
//         // Wildcard is not part of leftmost component of domain name
//         // Do not attempt to match (rfc6125 6.4.3.1)
//         return false;
//     }
//     if (wildcardPos != 0 || firstDotPos != 1) {
//         // Matching of wildcards such as baz*.example.com and b*z.example.com
//         // is optional. Maybe implement this in the future?
//         return false;
//     }
//     size_t domainNameFirstDotPos = domainName.find('.');
//     if (domainNameFirstDotPos == std::string::npos) {
//         return false;
//     }
//     return domainName.substr(domainNameFirstDotPos) == name.substr(firstDotPos);
// }

// // Verifies certificate provided by the peer to match specified SHA256 fingerprint
// bool WiFiSSLClientBeken::verify_ssl_fingerprint(sslclient_context *ssl_client, const char* fp, const char* domain_name)
// {
//     // Convert hex string to byte array
//     uint8_t fingerprint_local[32];
//     int len = strlen(fp);
//     int pos = 0;
//     for (size_t i = 0; i < sizeof(fingerprint_local); ++i) {
//         while (pos < len && ((fp[pos] == ' ') || (fp[pos] == ':'))) {
//             ++pos;
//         }
//         if (pos > len - 2) {
//             LT_DM(SSL, "pos:%d len:%d fingerprint too short", pos, len);
//             return false;
//         }
//         uint8_t high, low;
//         if (!parseHexNibble(fp[pos], &high) || !parseHexNibble(fp[pos+1], &low)) {
//             LT_DM(SSL, "pos:%d len:%d invalid hex sequence: %c%c", pos, len, fp[pos], fp[pos+1]);
//             return false;
//         }
//         pos += 2;
//         fingerprint_local[i] = low | (high << 4);
//     }

//     // Calculate certificate's SHA256 fingerprint
//     uint8_t fingerprint_remote[32];
//     if(!get_peer_fingerprint(ssl_client, fingerprint_remote))
//         return false;

//     // Check if fingerprints match
//     if (memcmp(fingerprint_local, fingerprint_remote, 32))
//     {
//         LT_DM(SSL, "fingerprint doesn't match");
//         return false;
//     }

//     // Additionally check if certificate has domain name if provided
//     if (domain_name)
//         return verify_ssl_dn(ssl_client, domain_name);
//     else
//         return true;
// }

// bool WiFiSSLClientBeken::get_peer_fingerprint(sslclient_context *ssl_client, uint8_t sha256[32])
// {
//     if (!ssl_client) {
//         LT_DM(SSL, "Invalid ssl_client pointer");
//         return false;
//     };

//     const mbedtls_x509_crt* crt = mbedtls_ssl_get_peer_cert(&ssl_client->ssl_ctx);
//     if (!crt) {
//         LT_DM(SSL, "Failed to get peer cert.");
//         return false;
//     };

//     mbedtls_sha256_context sha256_ctx;
//     mbedtls_sha256_init(&sha256_ctx);
//     mbedtls_sha256_starts(&sha256_ctx, false);
//     mbedtls_sha256_update(&sha256_ctx, crt->raw.p, crt->raw.len);
//     mbedtls_sha256_finish(&sha256_ctx, sha256);

//     return true;
// }

// // Checks if peer certificate has specified domain in CN or SANs
// bool WiFiSSLClientBeken::verify_ssl_dn(sslclient_context *ssl_client, const char* domain_name)
// {
//     LT_DM(SSL, "domain name: '%s'", (domain_name)?domain_name:"(null)");
//     std::string domain_name_str(domain_name);
//     std::transform(domain_name_str.begin(), domain_name_str.end(), domain_name_str.begin(), ::tolower);

//     // Get certificate provided by the peer
//     const mbedtls_x509_crt* crt = mbedtls_ssl_get_peer_cert(&ssl_client->ssl_ctx);

//     // Check for domain name in SANs
//     const mbedtls_x509_sequence* san = &crt->subject_alt_names;
//     while (san != nullptr)
//     {
//         std::string san_str((const char*)san->buf.p, san->buf.len);
//         std::transform(san_str.begin(), san_str.end(), san_str.begin(), ::tolower);

//         if (matchName(san_str, domain_name_str))
//             return true;

//         LT_DM(SSL, "SAN '%s': no match", san_str.c_str());

//         // Fetch next SAN
//         san = san->next;
//     }

//     // Check for domain name in CN
//     const mbedtls_asn1_named_data* common_name = &crt->subject;
//     while (common_name != nullptr)
//     {
//         // While iterating through DN objects, check for CN object
//         if (!MBEDTLS_OID_CMP(MBEDTLS_OID_AT_CN, &common_name->oid))
//         {
//             std::string common_name_str((const char*)common_name->val.p, common_name->val.len);

//             if (matchName(common_name_str, domain_name_str))
//                 return true;

//             LT_DM(SSL, "CN '%s': not match", common_name_str.c_str());
//         }

//         // Fetch next DN object
//         common_name = common_name->next;
//     }

//     return false;
// }

#endif