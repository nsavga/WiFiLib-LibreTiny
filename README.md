# LibreTiny WiFi Clients
Library consists of:
- A simpler HttpClient class which doesnt have cookies and other stuff which I didn't need for my project's use cases.
- WiFiClientRTL class which implements the WiFiClient for RTL8720 and RTL8710 chips. (Tested only on RTL8720CF (wbr3)) (This is mostly copied and refactored from https://github.com/ambiot/ambd_arduino WiFiClient implementation)
- WiFiSSLClientRTL class which implements the WiFiClientSecure for RTL8720 and RTL8710 chips. (Tested only on RTL8720CF (wbr3) by using the feature/realtek-update branch of LibreTiny) (This is mostly copied and refactored from https://github.com/ambiot/ambd_arduino WiFiSSLClient implementation)
- WiFiSSLClientBeken class which implements the WiFiClientSecure for BK72XX chips as it needed a separate logic. Copied and refactored from ESP32 arduino library. (Tested on BK7231S (wb3s))


Please check the platformio.ini file for the build_flags I used for MBEDTLS definitions which are needed for the library to enable ciphers.

WiFiClientSecure implementations work well with a self-signed certificate right now. They still have problems with more secure web apps and certificates.

IMPORTANT NOTE: All 3 WiFiClient inherited classes rely on changing the bool _connected field of LWIPClient class of LibreTiny to protected instead of private, so that they could access it during inheritance.. 

TODO:
- Find a way to add correct ciphers to work with LetsEncrypt and other systems, which are sending fatal alert now during the handshake. This is caused of the lack of correct ciphers on the client. It should be fixed by adding correct MBEDTLS_** definitions during compile time..
