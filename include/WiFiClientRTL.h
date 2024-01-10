#ifndef WifiClientRTL_h
#define WifiClientRTL_h

#include "Print.h"
#include "WiFiClient.h"
#include "IPAddress.h"
#include "server_drv.h"

class WiFiClientRTL : public WiFiClient {
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
        ServerDrv clientdrv;
        bool _is_connected;
        uint8_t data[DATA_LENTH];

        int recvTimeout;
};



#endif
