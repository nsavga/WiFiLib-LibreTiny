#if LT_ARD_HAS_WIFI

#include <Arduino.h>

#include <StreamString.h>
#include <base64.h>

#include "SimpleHttpClient.h"

/// Cookie jar support
#include <time.h>

SimpleHttpClient::SimpleHttpClient() {}

/**
 * destructor
 */
SimpleHttpClient::~SimpleHttpClient()
{
	if (_client)
	{
		_client->stop();
	}
	if (_currentHeaders)
	{
		delete[] _currentHeaders;
	}
}

void SimpleHttpClient::clear()
{
	_returnCode = 0;
	_size = -1;
	_headers = "";
}

/**
 * parsing the url for all needed parameters
 * @param client Client&
 * @param url String
 * @param https bool
 * @return success bool
 */
bool SimpleHttpClient::begin(WiFiClient &client, String url)
{

	_client = &client;

	// check for : (http: or https:)
	int index = url.indexOf(':');
	if (index < 0)
	{
		LT_IM(CLIENT, "failed to parse protocol");
		return false;
	}

	String protocol = url.substring(0, index);
	if (protocol != "http" && protocol != "https")
	{
		LT_IM(CLIENT, "unknown protocol '%s'", protocol.c_str());
		return false;
	}

	_port = (protocol == "https" ? 443 : 80);
	_secure = (protocol == "https");
	return beginInternal(url, protocol.c_str());
}

bool SimpleHttpClient::beginInternal(String url, const char *expectedProtocol)
{
	LT_IM(CLIENT, "url: %s", url.c_str());

	// check for : (http: or https:
	int index = url.indexOf(':');
	if (index < 0)
	{
		LT_IM(CLIENT, "failed to parse protocol");
		return false;
	}

	_protocol = url.substring(0, index);
	if (_protocol != expectedProtocol)
	{
		LT_IM(CLIENT, "unexpected protocol: %s, expected %s", _protocol.c_str(), expectedProtocol);
		return false;
	}

	url.remove(0, (index + 3)); // remove http:// or https://

	index = url.indexOf('/');
	if (index == -1)
	{
		index = url.length();
		url += '/';
	}
	String host = url.substring(0, index);
	url.remove(0, index); // remove host part

	// get Authorization
	index = host.indexOf('@');
	if (index >= 0)
	{
		// auth info
		String auth = host.substring(0, index);
		host.remove(0, index + 1); // remove auth part including @
		_base64Authorization = base64::encode(auth);
	}

	// get port
	index = host.indexOf(':');
	String the_host;
	if (index >= 0)
	{
		the_host = host.substring(0, index); // hostname
		host.remove(0, (index + 1));		 // remove hostname + :
		_port = host.toInt();				 // get port
	}
	else
	{
		the_host = host;
	}
	if (_host != the_host && connected())
	{
		LT_IM(CLIENT, "switching host from '%s' to '%s'. disconnecting first", _host.c_str(), the_host.c_str());
		_canReuse = false;
		disconnect(true);
	}
	_host = the_host;
	_uri = url;
	LT_IM(CLIENT, "protocol: %s, host: %s port: %d url: %s", _protocol.c_str(), _host.c_str(), _port, _uri.c_str());
	return true;
}

void SimpleHttpClient::end(void)
{
	disconnect(false);
	clear();
}

/**
 * disconnect
 * close the TCP socket
 */
void SimpleHttpClient::disconnect(bool preserveClient)
{
	if (connected())
	{
		if (_client->available() > 0)
		{
			LT_IM(CLIENT, "still data in buffer (%d), clean up.\n", _client->available());
			_client->flush();
		}

		if (_reuse && _canReuse)
		{
			LT_IM(CLIENT, "tcp keep open for reuse");
		}
		else
		{
			LT_IM(CLIENT, "tcp stop");
			_client->stop();
			if (!preserveClient)
			{
				_client = nullptr;
			}
		}
	}
	else
	{
		LT_IM(CLIENT, "tcp is closed\n");
	}
}

/**
 * connected
 * @return connected status
 */
bool SimpleHttpClient::connected()
{
	if (_client)
	{
		return ((_client->available() > 0) || _client->connected());
	}
	return false;
}

/**
 * try to reuse the connection to the server
 * keep-alive
 * @param reuse bool
 */
void SimpleHttpClient::setReuse(bool reuse)
{
	_reuse = reuse;
}

/**
 * set User Agent
 * @param userAgent const char *
 */
void SimpleHttpClient::setUserAgent(const String &userAgent)
{
	_userAgent = userAgent;
}

/**
 * set the Authorizatio for the http request
 * @param user const char *
 * @param password const char *
 */
void SimpleHttpClient::setAuthorization(const char *user, const char *password)
{
	if (user && password)
	{
		String auth = user;
		auth += ":";
		auth += password;
		_base64Authorization = base64::encode(auth);
	}
}

/**
 * set the Authorizatio for the http request
 * @param auth const char * base64
 */
void SimpleHttpClient::setAuthorization(const char *auth)
{
	if (auth)
	{
		_base64Authorization = auth;
	}
}

/**
 * set the Authorization type for the http request
 * @param authType const char *
 */
void SimpleHttpClient::setAuthorizationType(const char *authType)
{
	if (authType)
	{
		_authorizationType = authType;
	}
}

/**
 * set the timeout (ms) for establishing a connection to the server
 * @param connectTimeout int32_t
 */
void SimpleHttpClient::setConnectTimeout(int32_t connectTimeout)
{
	_connectTimeout = connectTimeout;
}

/**
 * set the timeout for the TCP connection
 * @param timeout unsigned int
 */
void SimpleHttpClient::setTimeout(uint16_t timeout)
{
	_tcpTimeout = timeout;
	if (connected())
	{
		_client->setTimeout((timeout + 500) / 1000);
	}
}

/**
 * use HTTP1.0
 * @param use
 */
void SimpleHttpClient::useHTTP10(bool useHTTP10)
{
	_useHTTP10 = useHTTP10;
	_reuse = !useHTTP10;
}

/**
 * send a GET request
 * @return http code
 */
int SimpleHttpClient::GET()
{
	return sendRequest("GET");
}

int SimpleHttpClient::POST(String payload)
{
	return sendRequest("POST", (uint8_t *)payload.c_str(), payload.length());
}

int SimpleHttpClient::sendRequest(const char *type, String payload)
{
	return sendRequest(type, (uint8_t *)payload.c_str(), payload.length());
}

/**
 * sendRequest
 * @param type const char *     "GET", "POST", ....
 * @param payload uint8_t *     data for the message body if null not send
 * @param size size_t           size for the message body if 0 not send
 * @return -1 if no info or > 0 when Content-Length is set by server
 */
int SimpleHttpClient::sendRequest(const char *type, uint8_t *payload, size_t size)
{
	int code;
	bool redirect = false;
	uint16_t redirectCount = 0;

	// wipe out any existing headers from previous request
	for (size_t i = 0; i < _headerKeysCount; i++)
	{
		if (_currentHeaders[i].value.length() > 0)
		{
			_currentHeaders[i].value = ""; // LT: changed from clear()
		}
	}

	LT_IM(CLIENT, "request type: '%s' redirCount: %d\n", type, redirectCount);

	// connect to server
	if (!connect())
	{
		return returnError(HTTPC_ERROR_CONNECTION_REFUSED);
	}

	if (payload && size > 0)
	{
		addHeader(F("Content-Length"), String(size));
	}

	// send Header
	if (!sendHeader(type))
	{
		return returnError(HTTPC_ERROR_SEND_HEADER_FAILED);
	}

	// send Payload if needed
	if (payload && size > 0)
	{
		if (_client->write(&payload[0], size) != size)
		{
			return returnError(HTTPC_ERROR_SEND_PAYLOAD_FAILED);
		}
	}

	code = handleHeaderResponse();
	LT_IM(CLIENT, "sendRequest code=%d\n", code);

	// handle Server Response (Header)
	return returnError(code);
}

/**
 * sendRequest
 * @param type const char *     "GET", "POST", ....
 * @param stream Stream *       data stream for the message body
 * @param size size_t           size for the message body if 0 not Content-Length is send
 * @return -1 if no info or > 0 when Content-Length is set by server
 */
int SimpleHttpClient::sendRequest(const char *type, Stream *stream, size_t size)
{

	if (!stream)
	{
		return returnError(HTTPC_ERROR_NO_STREAM);
	}

	// connect to server
	if (!connect())
	{
		return returnError(HTTPC_ERROR_CONNECTION_REFUSED);
	}

	if (size > 0)
	{
		addHeader("Content-Length", String(size));
	}

	// send Header
	if (!sendHeader(type))
	{
		return returnError(HTTPC_ERROR_SEND_HEADER_FAILED);
	}

	int buff_size = HTTP_TCP_BUFFER_SIZE;

	int len = size;
	int bytesWritten = 0;

	if (len == 0)
	{
		len = -1;
	}

	// if possible create smaller buffer then HTTP_TCP_BUFFER_SIZE
	if ((len > 0) && (len < HTTP_TCP_BUFFER_SIZE))
	{
		buff_size = len;
	}

	// create buffer for read
	uint8_t *buff = (uint8_t *)malloc(buff_size);

	if (buff)
	{
		// read all data from stream and send it to server
		while (connected() && (stream->available() > -1) && (len > 0 || len == -1))
		{

			// get available data size
			int sizeAvailable = stream->available();

			if (sizeAvailable)
			{

				int readBytes = sizeAvailable;

				// read only the asked bytes
				if (len > 0 && readBytes > len)
				{
					readBytes = len;
				}

				// not read more the buffer can handle
				if (readBytes > buff_size)
				{
					readBytes = buff_size;
				}

				// read data
				int bytesRead = stream->readBytes(buff, readBytes);

				// write it to Stream
				int bytesWrite = _client->write((const uint8_t *)buff, bytesRead);
				bytesWritten += bytesWrite;

				// are all Bytes a writen to stream ?
				if (bytesWrite != bytesRead)
				{
					LT_IM(CLIENT, "short write, asked for %d but got %d retry...", bytesRead, bytesWrite);

					// check for write error
					if (_client->getWriteError())
					{
						LT_IM(CLIENT, "stream write error %d", _client->getWriteError());

						// reset write error for retry
						_client->clearWriteError();
					}

					// some time for the stream
					delay(1);

					int leftBytes = (readBytes - bytesWrite);

					// retry to send the missed bytes
					bytesWrite = _client->write((const uint8_t *)(buff + bytesWrite), leftBytes);
					bytesWritten += bytesWrite;

					if (bytesWrite != leftBytes)
					{
						// failed again
						LT_IM(CLIENT, "short write, asked for %d but got %d failed.", leftBytes, bytesWrite);
						free(buff);
						return returnError(HTTPC_ERROR_SEND_PAYLOAD_FAILED);
					}
				}

				// check for write error
				if (_client->getWriteError())
				{
					LT_IM(CLIENT, "stream write error %d", _client->getWriteError());
					free(buff);
					return returnError(HTTPC_ERROR_SEND_PAYLOAD_FAILED);
				}

				// count bytes to read left
				if (len > 0)
				{
					len -= readBytes;
				}

				delay(0);
			}
			else
			{
				delay(1);
			}
		}

		free(buff);

		if (size && (int)size != bytesWritten)
		{
			LT_IM(CLIENT, "Stream payload bytesWritten %d and size %d mismatch!.", bytesWritten, size);
			LT_IM(CLIENT, "ERROR SEND PAYLOAD FAILED!");
			return returnError(HTTPC_ERROR_SEND_PAYLOAD_FAILED);
		}
		else
		{
			LT_IM(CLIENT, "Stream payload written: %d", bytesWritten);
		}
	}
	else
	{
		LT_IM(CLIENT, "too less ram! need %d", HTTP_TCP_BUFFER_SIZE);
		return returnError(HTTPC_ERROR_TOO_LESS_RAM);
	}

	// handle Server Response (Header)
	return returnError(handleHeaderResponse());
}

/**
 * size of message body / payload
 * @return -1 if no info or > 0 when Content-Length is set by server
 */
int SimpleHttpClient::getSize(void)
{
	return _size;
}

/**
 * returns the stream of the tcp connection
 * @return WiFiClient
 */
WiFiClient &SimpleHttpClient::getStream(void)
{
	if (connected())
	{
		return *_client;
	}

	LT_IM(CLIENT, "getStream: not connected");
	static WiFiClient empty;
	return empty;
}

/**
 * returns a pointer to the stream of the tcp connection
 * @return WiFiClient*
 */
WiFiClient *SimpleHttpClient::getStreamPtr(void)
{
	if (connected())
	{
		return _client;
	}

	LT_IM(CLIENT, "getStreamPtr: not connected");
	return nullptr;
}

/**
 * write all  message body / payload to Stream
 * @param stream Stream *
 * @return bytes written ( negative values are error codes )
 */
int SimpleHttpClient::writeToStream(Stream *stream)
{

	if (!stream)
	{
		return returnError(HTTPC_ERROR_NO_STREAM);
	}

	if (!connected())
	{
		return returnError(HTTPC_ERROR_NOT_CONNECTED);
	}

	// get length of document (is -1 when Server sends no Content-Length header)
	int len = _size;
	int ret = 0;

	if (_transferEncoding == HTTPC_TE_IDENTITY)
	{
		ret = writeToStreamDataBlock(stream, len);

		// have we an error?
		if (ret < 0)
		{
			return returnError(ret);
		}
	}
	else if (_transferEncoding == HTTPC_TE_CHUNKED)
	{
		int size = 0;
		while (1)
		{
			if (!connected())
			{
				return returnError(HTTPC_ERROR_CONNECTION_LOST);
			}
			String chunkHeader = _client->readStringUntil('\n');

			if (chunkHeader.length() <= 0)
			{
				return returnError(HTTPC_ERROR_READ_TIMEOUT);
			}

			chunkHeader.trim(); // remove \r

			// read size of chunk
			len = (uint32_t)strtol((const char *)chunkHeader.c_str(), NULL, 16);
			size += len;
			LT_IM(CLIENT, " read chunk len: %d", len);

			// data left?
			if (len > 0)
			{
				int r = writeToStreamDataBlock(stream, len);
				if (r < 0)
				{
					// error in writeToStreamDataBlock
					return returnError(r);
				}
				ret += r;
			}
			else
			{

				// if no length Header use global chunk size
				if (_size <= 0)
				{
					_size = size;
				}

				// check if we have write all data out
				if (ret != _size)
				{
					return returnError(HTTPC_ERROR_STREAM_WRITE);
				}
				break;
			}

			// read trailing \r\n at the end of the chunk
			char buf[2];
			auto trailing_seq_len = _client->readBytes((uint8_t *)buf, 2);
			if (trailing_seq_len != 2 || buf[0] != '\r' || buf[1] != '\n')
			{
				return returnError(HTTPC_ERROR_READ_TIMEOUT);
			}

			delay(0);
		}
	}
	else
	{
		return returnError(HTTPC_ERROR_ENCODING);
	}

	//    end();
	disconnect(true);
	return ret;
}

/**
 * return all payload as String (may need lot of ram or trigger out of memory!)
 * @return String
 */
String SimpleHttpClient::getString(void)
{
	// _size can be -1 when Server sends no Content-Length header
	if (_size > 0 || _size == -1)
	{
		StreamString sstring;
		// try to reserve needed memory (noop if _size == -1)
		if (sstring.reserve((_size + 1)))
		{
			writeToStream(&sstring);
			return sstring;
		}
		else
		{
			LT_IM(CLIENT, "not enough memory to reserve a string! need: %d", (_size + 1));
		}
	}

	return "";
}

/**
 * converts error code to String
 * @param error int
 * @return String
 */
String SimpleHttpClient::errorToString(int error)
{
	switch (error)
	{
	case HTTPC_ERROR_CONNECTION_REFUSED:
		return F("connection refused");
	case HTTPC_ERROR_SEND_HEADER_FAILED:
		return F("send header failed");
	case HTTPC_ERROR_SEND_PAYLOAD_FAILED:
		return F("send payload failed");
	case HTTPC_ERROR_NOT_CONNECTED:
		return F("not connected");
	case HTTPC_ERROR_CONNECTION_LOST:
		return F("connection lost");
	case HTTPC_ERROR_NO_STREAM:
		return F("no stream");
	case HTTPC_ERROR_NO_HTTP_SERVER:
		return F("no HTTP server");
	case HTTPC_ERROR_TOO_LESS_RAM:
		return F("too less ram");
	case HTTPC_ERROR_ENCODING:
		return F("Transfer-Encoding not supported");
	case HTTPC_ERROR_STREAM_WRITE:
		return F("Stream write error");
	case HTTPC_ERROR_READ_TIMEOUT:
		return F("read Timeout");
	default:
		return String();
	}
}

/**
 * adds Header to the request
 * @param name
 * @param value
 * @param first
 */
void SimpleHttpClient::addHeader(const String &name, const String &value, bool first, bool replace)
{
	// not allow set of Header handled by code
	if (!name.equalsIgnoreCase(F("Connection")) && !name.equalsIgnoreCase(F("User-Agent")) &&
		!name.equalsIgnoreCase(F("Host")) &&
		!(name.equalsIgnoreCase(F("Authorization")) && _base64Authorization.length()))
	{

		String headerLine = name;
		headerLine += ": ";

		if (replace)
		{
			int headerStart = _headers.indexOf(headerLine);
			if (headerStart != -1 && (headerStart == 0 || _headers[headerStart - 1] == '\n'))
			{
				int headerEnd = _headers.indexOf('\n', headerStart);
				_headers = _headers.substring(0, headerStart) + _headers.substring(headerEnd + 1);
			}
		}

		headerLine += value;
		headerLine += "\r\n";
		if (first)
		{
			_headers = headerLine + _headers;
		}
		else
		{
			_headers += headerLine;
		}
	}
}

void SimpleHttpClient::collectHeaders(const char *headerKeys[], const size_t headerKeysCount)
{
	_headerKeysCount = headerKeysCount;
	if (_currentHeaders)
	{
		delete[] _currentHeaders;
	}
	_currentHeaders = new RequestArgument[_headerKeysCount];
	for (size_t i = 0; i < _headerKeysCount; i++)
	{
		_currentHeaders[i].key = headerKeys[i];
	}
}

String SimpleHttpClient::header(const char *name)
{
	for (size_t i = 0; i < _headerKeysCount; ++i)
	{
		if (_currentHeaders[i].key == name)
		{
			return _currentHeaders[i].value;
		}
	}
	return String();
}

String SimpleHttpClient::header(size_t i)
{
	if (i < _headerKeysCount)
	{
		return _currentHeaders[i].value;
	}
	return String();
}

String SimpleHttpClient::headerName(size_t i)
{
	if (i < _headerKeysCount)
	{
		return _currentHeaders[i].key;
	}
	return String();
}

int SimpleHttpClient::headers()
{
	return _headerKeysCount;
}

bool SimpleHttpClient::hasHeader(const char *name)
{
	for (size_t i = 0; i < _headerKeysCount; ++i)
	{
		if ((_currentHeaders[i].key == name) && (_currentHeaders[i].value.length() > 0))
		{
			return true;
		}
	}
	return false;
}

/**
 * init TCP connection and handle ssl verify if needed
 * @return true if connection is ok
 */
bool SimpleHttpClient::connect(void)
{
	if (connected())
	{
		if (_reuse)
		{
			LT_IM(CLIENT, "already connected, reusing connection");
		}
		else
		{
			LT_IM(CLIENT, "already connected, try reuse!");
		}
		while (_client->available() > 0)
		{
			_client->read();
		}
		return true;
	}

	if (!_client)
	{
		LT_IM(CLIENT, "HTTPClient::begin was not called or returned error");
		return false;
	}

	if (!_client->connect(_host.c_str(), _port, _connectTimeout))
	{
		LT_IM(CLIENT, "failed connect to %s:%u", _host.c_str(), _port);
		return false;
	}

	// set Timeout for WiFiClient and for Stream::readBytesUntil() and Stream::readStringUntil()
	_client->setTimeout((_tcpTimeout + 500) / 1000);

	LT_IM(CLIENT, " connected to %s:%u", _host.c_str(), _port);

	/*
	#ifdef ESP8266
		_client->setNoDelay(true);
	#endif
	 */
	return connected();
}

/**
 * sends HTTP request header
 * @param type (GET, POST, ...)
 * @return status
 */
bool SimpleHttpClient::sendHeader(const char *type)
{
	if (!connected())
	{
		return false;
	}

	String header = String(type) + " " + _uri + F(" HTTP/1.");

	if (_useHTTP10)
	{
		header += "0";
	}
	else
	{
		header += "1";
	}

	header += String(F("\r\nHost: ")) + _host;
	if (_port != 80 && _port != 443)
	{
		header += ':';
		header += String(_port);
	}
	header += String(F("\r\nUser-Agent: ")) + _userAgent + F("\r\nConnection: ");

	if (_reuse)
	{
		header += F("keep-alive");
	}
	else
	{
		header += F("close");
	}
	header += "\r\n";

	if (!_useHTTP10)
	{
		header += F("Accept-Encoding: identity;q=1,chunked;q=0.1,*;q=0\r\n");
	}

	if (_base64Authorization.length())
	{
		_base64Authorization.replace("\n", "");
		header += F("Authorization: ");
		header += _authorizationType;
		header += " ";
		header += _base64Authorization;
		header += "\r\n";
	}

	header += _headers + "\r\n";

	return (_client->write((const uint8_t *)header.c_str(), header.length()) == header.length());
}

/**
 * reads the response from the server
 * @return int http code
 */
int SimpleHttpClient::handleHeaderResponse()
{

	if (!connected())
	{
		return HTTPC_ERROR_NOT_CONNECTED;
	}

	_returnCode = 0;
	_size = -1;
	_canReuse = _reuse;

	String transferEncoding;

	_transferEncoding = HTTPC_TE_IDENTITY;
	unsigned long lastDataTime = millis();
	bool firstLine = true;
	String date;

	while (connected())
	{
		size_t len = _client->available();
		if (len > 0)
		{
			String headerLine = _client->readStringUntil('\n');
			headerLine.trim(); // remove \r

			lastDataTime = millis();

			LT_IM(CLIENT, "RX: '%s'", headerLine.c_str());

			if (firstLine)
			{
				firstLine = false;
				if (_canReuse && headerLine.startsWith("HTTP/1."))
				{
					_canReuse = (headerLine[sizeof "HTTP/1." - 1] != '0');
				}
				int codePos = headerLine.indexOf(' ') + 1;
				_returnCode = headerLine.substring(codePos, headerLine.indexOf(' ', codePos)).toInt();
			}
			else if (headerLine.indexOf(':'))
			{
				String headerName = headerLine.substring(0, headerLine.indexOf(':'));
				String headerValue = headerLine.substring(headerLine.indexOf(':') + 1);
				headerValue.trim();

				if (headerName.equalsIgnoreCase("Date"))
				{
					date = headerValue;
				}

				if (headerName.equalsIgnoreCase("Content-Length"))
				{
					_size = headerValue.toInt();
					LT_IM(SSL, "SIZE SET TO %d", _size);
				}

				if (_canReuse && headerName.equalsIgnoreCase("Connection"))
				{
					if (headerValue.indexOf("close") >= 0 && headerValue.indexOf("keep-alive") < 0)
					{
						_canReuse = false;
					}
				}

				if (headerName.equalsIgnoreCase("Transfer-Encoding"))
				{
					transferEncoding = headerValue;
				}

				if (headerName.equalsIgnoreCase("Location"))
				{
					_location = headerValue;
				}

				for (size_t i = 0; i < _headerKeysCount; i++)
				{
					if (_currentHeaders[i].key.equalsIgnoreCase(headerName))
					{
						// Uncomment the following lines if you need to add support for multiple headers with the same
						// key: if (!_currentHeaders[i].value.isEmpty()) {
						//     // Existing value, append this one with a comma
						//     _currentHeaders[i].value += ',';
						//     _currentHeaders[i].value += headerValue;
						// } else {
						_currentHeaders[i].value = headerValue;
						// }
						break; // We found a match, stop looking
					}
				}
			}

			if (headerLine == "")
			{
				LT_IM(CLIENT, "code: %d", _returnCode);

				if (_size > 0)
				{
					LT_IM(CLIENT, "size: %d", _size);
				}

				if (transferEncoding.length() > 0)
				{
					LT_IM(CLIENT, "Transfer-Encoding: %s", transferEncoding.c_str());
					if (transferEncoding.equalsIgnoreCase("chunked"))
					{
						_transferEncoding = HTTPC_TE_CHUNKED;
					}
					else if (transferEncoding.equalsIgnoreCase("identity"))
					{
						_transferEncoding = HTTPC_TE_IDENTITY;
					}
					else
					{
						return HTTPC_ERROR_ENCODING;
					}
				}
				else
				{
					_transferEncoding = HTTPC_TE_IDENTITY;
				}

				if (_returnCode)
				{
					return _returnCode;
				}
				else
				{
					LT_IM(CLIENT, "Remote host is not an HTTP Server!");
					return HTTPC_ERROR_NO_HTTP_SERVER;
				}
			}
		}
		else
		{
			if ((millis() - lastDataTime) > _tcpTimeout)
			{
				return HTTPC_ERROR_READ_TIMEOUT;
			}
			delay(10);
		}
	}

	return HTTPC_ERROR_CONNECTION_LOST;
}

/**
 * write one Data Block to Stream
 * @param stream Stream *
 * @param size int
 * @return < 0 = error >= 0 = size written
 */
int SimpleHttpClient::writeToStreamDataBlock(Stream *stream, int size)
{
	int buff_size = HTTP_TCP_BUFFER_SIZE;
	int len = size;
	int bytesWritten = 0;

	// if possible create smaller buffer then HTTP_TCP_BUFFER_SIZE
	if ((len > 0) && (len < HTTP_TCP_BUFFER_SIZE))
	{
		buff_size = len;
	}

	// create buffer for read
	uint8_t *buff = (uint8_t *)malloc(buff_size);

	if (buff)
	{
		// read all data from server
		while (connected() && (len > 0 || len == -1))
		{

			// get available data size
			size_t sizeAvailable = _client->available();

			if (sizeAvailable)
			{

				int readBytes = sizeAvailable;

				// read only the asked bytes
				if (len > 0 && readBytes > len)
				{
					readBytes = len;
				}

				// not read more the buffer can handle
				if (readBytes > buff_size)
				{
					readBytes = buff_size;
				}

				// stop if no more reading
				if (readBytes == 0)
					break;

				// read data
				int bytesRead = _client->readBytes(buff, readBytes);

				// write it to Stream
				int bytesWrite = stream->write(buff, bytesRead);
				bytesWritten += bytesWrite;

				// are all Bytes a writen to stream ?
				if (bytesWrite != bytesRead)
				{
					LT_IM(CLIENT, "short write asked for %d but got %d retry...", bytesRead, bytesWrite);

					// check for write error
					if (stream->getWriteError())
					{
						LT_IM(CLIENT, "stream write error %d", stream->getWriteError());

						// reset write error for retry
						stream->clearWriteError();
					}

					// some time for the stream
					delay(1);

					int leftBytes = (readBytes - bytesWrite);

					// retry to send the missed bytes
					bytesWrite = stream->write((buff + bytesWrite), leftBytes);
					bytesWritten += bytesWrite;

					if (bytesWrite != leftBytes)
					{
						// failed again
						LT_IM(CLIENT, "short write asked for %d but got %d failed.", leftBytes, bytesWrite);
						free(buff);
						return HTTPC_ERROR_STREAM_WRITE;
					}
				}

				// check for write error
				if (stream->getWriteError())
				{
					LT_IM(CLIENT, "stream write error %d", stream->getWriteError());
					free(buff);
					return HTTPC_ERROR_STREAM_WRITE;
				}

				// count bytes to read left
				if (len > 0)
				{
					len -= readBytes;
				}

				delay(0);
			}
			else
			{
				delay(1);
			}
		}

		free(buff);

		LT_IM(CLIENT, "connection closed or file end (written: %d).", bytesWritten);

		if ((size > 0) && (size != bytesWritten))
		{
			LT_IM(CLIENT, "bytesWritten %d and size %d mismatch!.", bytesWritten, size);
			return HTTPC_ERROR_STREAM_WRITE;
		}
	}
	else
	{
		LT_IM(CLIENT, "too less ram! need %d", HTTP_TCP_BUFFER_SIZE);
		return HTTPC_ERROR_TOO_LESS_RAM;
	}

	return bytesWritten;
}

/**
 * called to handle error return, may disconnect the connection if still exists
 * @param error
 * @return error
 */
int SimpleHttpClient::returnError(int error)
{
	if (error < 0)
	{
		LT_IM(CLIENT, "error(%d): %s", error, errorToString(error).c_str());
		if (connected())
		{
			LT_IM(CLIENT, "tcp stop");
			_client->stop();
		}
	}
	return error;
}

void SimpleHttpClient::setFollowRedirects(followRedirects_t follow)
{
	_followRedirects = follow;
}

void SimpleHttpClient::setRedirectLimit(uint16_t limit)
{
	_redirectLimit = limit;
}

/**
 * set the URL to a new value. Handy for following redirects.
 * @param url
 */
bool SimpleHttpClient::setURL(const String &url)
{
	// if the new location is only a path then only update the URI
	if (url && url[0] == '/')
	{
		_uri = url;
		clear();
		return true;
	}

	if (!url.startsWith(_protocol + ':'))
	{
		LT_IM(CLIENT, "new URL not the same protocol, expected '%s', URL: '%s'\n", _protocol.c_str(), url.c_str());
		return false;
	}

	// check if the port is specified
	int indexPort = url.indexOf(':', 6); // find the first ':' excluding the one from the protocol
	int indexURI = url.indexOf('/', 7);	 // find where the URI starts to make sure the ':' is not part of it
	if (indexPort == -1 || indexPort > indexURI)
	{
		// the port is not specified
		_port = (_protocol == "https" ? 443 : 80);
	}

	// disconnect but preserve _client.
	// Also have to keep the connection otherwise it will free some of the memory used by _client
	// and will blow up later when trying to do _client->available() or similar
	_canReuse = true;
	disconnect(true);
	return beginInternal(url, _protocol.c_str());
}

const String &SimpleHttpClient::getLocation(void)
{
	return _location;
}

#endif // LT_ARD_HAS_WIFI
