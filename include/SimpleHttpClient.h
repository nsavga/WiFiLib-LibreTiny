#ifndef SimpleHttpClient_H_
#define SimpleHttpClient_H_

#include <Arduino.h>
#include <WiFiClient.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <memory>

/// Cookie jar support
#include <vector>

#define HTTPCLIENT_DEFAULT_TCP_TIMEOUT (5000)

/// HTTP client errors
#define HTTPC_ERROR_CONNECTION_REFUSED	(-1)
#define HTTPC_ERROR_SEND_HEADER_FAILED	(-2)
#define HTTPC_ERROR_SEND_PAYLOAD_FAILED (-3)
#define HTTPC_ERROR_NOT_CONNECTED		(-4)
#define HTTPC_ERROR_CONNECTION_LOST		(-5)
#define HTTPC_ERROR_NO_STREAM			(-6)
#define HTTPC_ERROR_NO_HTTP_SERVER		(-7)
#define HTTPC_ERROR_TOO_LESS_RAM		(-8)
#define HTTPC_ERROR_ENCODING			(-9)
#define HTTPC_ERROR_STREAM_WRITE		(-10)
#define HTTPC_ERROR_READ_TIMEOUT		(-11)

/// size for the stream handling
#define HTTP_TCP_BUFFER_SIZE (1460)




class SimpleHttpClient {
  public:
	SimpleHttpClient();
	~SimpleHttpClient();

	/*
	 * Since both begin() functions take a reference to client as a parameter, you need to
	 * ensure the client object lives the entire time of the HTTPClient
	 */
	bool begin(WiFiClient &client, String url);

	void end(void);

	bool connected(void);

	void setReuse(bool reuse); /// keep-alive
	void setUserAgent(const String &userAgent);
	void setAuthorization(const char *user, const char *password);
	void setAuthorization(const char *auth);
	void setAuthorizationType(const char *authType);
	void setConnectTimeout(int32_t connectTimeout);
	void setTimeout(uint16_t timeout);

	// Redirections
	void setFollowRedirects(followRedirects_t follow);
	void setRedirectLimit(uint16_t limit); // max redirects to follow for a single request

	bool setURL(const String &url);
	void useHTTP10(bool usehttp10 = true);

	/// request handling
	int GET();
	int POST(String payload);
	
	int sendRequest(const char *type, String payload);
	int sendRequest(const char *type, uint8_t *payload = NULL, size_t size = 0);
	int sendRequest(const char *type, Stream *stream, size_t size = 0);

	void addHeader(const String &name, const String &value, bool first = false, bool replace = true);

	/// Response handling
	void collectHeaders(const char *headerKeys[], const size_t headerKeysCount);
	String header(const char *name);  // get request header value by name
	String header(size_t i);		  // get request header value by number
	String headerName(size_t i);	  // get request header name by number
	int headers();					  // get header count
	bool hasHeader(const char *name); // check if header exists

	int getSize(void);
	const String &getLocation(void);

	WiFiClient &getStream(void);
	WiFiClient *getStreamPtr(void);
	int writeToStream(Stream *stream);
	String getString(void);

	static String errorToString(int error);

  protected:
	struct RequestArgument {
		String key;
		String value;
	};

	bool beginInternal(String url, const char *expectedProtocol);
	void disconnect(bool preserveClient = false);
	void clear();
	int returnError(int error);
	bool connect(void);
	bool sendHeader(const char *type);
	int handleHeaderResponse();
	int writeToStreamDataBlock(Stream *stream, int len);

	WiFiClient *_client = nullptr;

	/// request handling
	String _host;
	uint16_t _port			= 0;
	int32_t _connectTimeout = -1;
	bool _reuse				= false;
	uint16_t _tcpTimeout	= HTTPCLIENT_DEFAULT_TCP_TIMEOUT;
	bool _useHTTP10			= false;
	bool _secure			= false;

	String _uri;
	String _protocol;
	String _headers;
	String _userAgent = "ESP32HTTPClient";
	String _base64Authorization;
	String _authorizationType = "Basic";

	/// Response handling
	RequestArgument *_currentHeaders = nullptr;
	size_t _headerKeysCount			 = 0;

	int _returnCode					   = 0;
	int _size						   = -1;
	bool _canReuse					   = false;
	followRedirects_t _followRedirects = HTTPC_DISABLE_FOLLOW_REDIRECTS;
	uint16_t _redirectLimit			   = 10;
	String _location;
	transferEncoding_t _transferEncoding = HTTPC_TE_IDENTITY;
};

#endif /* HTTPClient_H_ */
