#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <PubSubClient.h>
#include <time.h>

const char* WIFI_SSID = "ZT-IOT";
const char* WIFI_PASS = "ztgateway2026";
const char* MQTT_HOST = "10.42.0.1";
const int   MQTT_PORT = 8883;
const char* DEVICE_ID = "esp32-01";

static const char CA_CERT[] PROGMEM = R"EOF(
-----BEGIN CERTIFICATE-----
MIIDVzCCAj+gAwIBAgIUJu0MTUdHaKCzdQ42SlbKL36mKU8wDQYJKoZIhvcNAQEL
BQAwOzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5ZMQ0wCwYDVQQKDARaVEdXMRAw
DgYDVQQDDAd6dGd3LWNhMB4XDTI2MDkyNDIzMzIyNVoXDTM2MDkyMTIzMzIyNVow
OzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5ZMQ0wCwYDVQQKDARaVEdXMRAwDgYD
VQQDDAd6dGd3LWNhMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu3LF
isKuLoHQNRn96Y8o2HBnevSLwlexq8Lsn61E5Jn8+E67OIF0T+aWeufAe62T6X51
BiUE5Xp4/SvLqysGMpxzu84aejZFItKMQc9NcQby91dJBmCwIPuhTSjRHGmFX4vy
I4R33K0Yimc7gieY/HifpLPznhbvPClAGg+nsijtorJ9nZ05VHlCz3WRy9gVUHvI
xqabPTq7U4WpG8v2iMbwSD/y04VaKe+eO/FwdPPHVeIjL70JNkcVKQJEC9C0XNwV
7wiRJgQGGqR31NOqLxU7eu+/UOWAbrjX8SuGMDxAOyIBqufZmTqaojmVRNlLuyDq
f8lWTXD4FK6hMV5t7QIDAQABo1MwUTAdBgNVHQ4EFgQUjny+qyaa9g2dRvUbuev3
ksrVjdowHwYDVR0jBBgwFoAUjny+qyaa9g2dRvUbuev3ksrVjdowDwYDVR0TAQH/
BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAZPE8yDORj1q6fAadVW8JsHMhoaxp
GU/9iui1D2CQYDUwK++dV9VzLq6OJluEB+0yDTO6POpJA88olRGsyUDoAHWsvyrF
tFQli1J6bWohxovWZI6g0rfaZD6+X1ytvZMH0P3tuWKCMGPFQCCyvHJHba1Icwgi
dAlxvFgpDQwFK75DRrtF8i1SttOpoS2VjXFSx3UEesQJwD8tOyj39bYbK+ObAP8l
MnC9Oc0LmMTu4szV7NEAVh1KIWVDibWQ+czToUT7Pku1OOISoEQZ4vpH6F4txHuM
p2WqV/2aBwkF8kDSCI01rI6OwdlH7Py/neYtAsM506Q5aYZccmD+iK6lWg==
-----END CERTIFICATE-----
)EOF";

static const char CLIENT_CERT[] PROGMEM = R"EOF(
-----BEGIN CERTIFICATE-----
MIIDRzCCAi+gAwIBAgIUZ3IfFdMR0W+NUjBaenwH0VdAYzYwDQYJKoZIhvcNAQEL
BQAwOzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5ZMQ0wCwYDVQQKDARaVEdXMRAw
DgYDVQQDDAd6dGd3LWNhMB4XDTI2MDkyNDIzMzI1M1oXDTM2MDkyMTIzMzI1M1ow
PDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5ZMQ0wCwYDVQQKDARaVEdXMREwDwYD
VQQDDAhlc3AzMi0wMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK+U
7xykHRFUFgMI06XQQOVMGdg6kvGHS1NTpZpxJNrzHjroWydO2c8wmL9cGoubzWQC
kxmJrCFWNVDCBXJJq2EhWKJAsy73MQ9fvyz1VNtSlDMczHXdldJHzNxz4p9rM7bu
KemLIqTFzB/Fz1lP8jWmIl/tu4hiPLUEToFJDt9h/bKmRwKUp5jF51MsNhbw4QDo
XvDrcRQJ3L/UH7VTSRiGKnMpQB3UpwIdC9EtcaJkboFtr03nPKY82n4qv4YLM8De
oyWKMIqLdpbQwFKkhWrmdxsXzTY/21Cz8QQ6u02XxIQQgxMyIiFdOUz5q4GMT7O8
tdmBNdNccEKnkP3/IxECAwEAAaNCMEAwHQYDVR0OBBYEFFnbUHEOHMXNikuSVL8d
98CaVD9gMB8GA1UdIwQYMBaAFI58vqsmmvYNnUb1G7nr95LK1Y3aMA0GCSqGSIb3
DQEBCwUAA4IBAQCciX+mETOJwFH7581hS6tOyk6ZKlSLaX3RRJDPJ2weGWFMybfd
fJWh56u8nbMc17CXUPVdJyPXcdzr8KSPdBNHUkHbpJlFOFOC3lArRMZ7aBf/bfMX
SunC7bW6qhiw6t7nZkvacoJc7iPN9FNtQzxV0hsg9Z/AWaFnixRw0EIbATVeZ7QA
BZ38Fb7vwt5ttaKAksfT1DzAeMeR5MFI9vEptfDznPGo0dWj5R7wwmXrUnuqVn/+
5+FY5BgCXgzPKQIQ9QQfVU8UsfZUdiT+vYHmcsy69/m+OfuszZFI1IuxRd2urgLv
OW9TgnSs4JsG03U8Ifug/pzvROL1PC33Szi5
-----END CERTIFICATE-----
)EOF";

static const char CLIENT_KEY[] PROGMEM = R"EOF(
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCvlO8cpB0RVBYD
CNOl0EDlTBnYOpLxh0tTU6WacSTa8x466FsnTtnPMJi/XBqLm81kApMZiawhVjVQ
wgVySathIViiQLMu9zEPX78s9VTbUpQzHMx13ZXSR8zcc+KfazO27inpiyKkxcwf
xc9ZT/I1piJf7buIYjy1BE6BSQ7fYf2ypkcClKeYxedTLDYW8OEA6F7w63EUCdy/
1B+1U0kYhipzKUAd1KcCHQvRLXGiZG6Bba9N5zymPNp+Kr+GCzPA3qMlijCKi3aW
0MBSpIVq5ncbF802P9tQs/EEOrtNl8SEEIMTMiIhXTlM+auBjE+zvLXZgTXTXHBC
p5D9/yMRAgMBAAECggEAFiKKemveFj8pfzxvoim85KtRXscTm0tZHaof6HZ3FPst
RnPgefYg01PnDcjIt+zuWbtRXBjVEGbT1dh/40aSSm5vxBSwAi27i5qgeUR8bCHe
+QqaZAmJR7cxhmE9oqdbH6aqtfyKY4dkEmVXnITNniHRl5Ja3/iyeoeOdhIFw/db
APCBFghyW5DbjmLRdgD6p2r0Irss6BZGKXZAg6fqdUudkmqhujtbCJqjCErkjlL9
oJoCdl7vu0OagcbT/RvfecaEAt8LoKBBlZRhqoHnXP6BqwSzdhHtUrb/ZebMmeg4
uBvCLXL7A752hXSwsmqpyH6d8BCQhP0KuhIKYE+l2QKBgQDgANlK2+F0ZZs58RE/
Rc37RfReAjgd7v4RmBprPN4yhuES8pirkZ2VExky9Ils9yWKR/cl1Tf7JO9qiwvg
gtM5EclQVqzYKiZGDtZOQQBDr41nI7ZvfcPf2k/O7xKDoSgrDAJ8iuSzMqQHusRv
Q6SybG1my731a1QfDRm9oW34PwKBgQDIqXMwYCk928AtYCwyWFedJovIfLI4dVK9
9rGmSDskaavxk0YGfBG5gMefgqlyAlQGYgDCmK4TRNcE0mu4x1wHJp/lYyCRVmvw
FkN4XMNetMh2+dkEJkDB3zw4fPOWxr91w4Uft4zQk1VJ/XD4WZA61WVLgBUoj8Tm
9RS4tBGQrwKBgHmkXFuHfi4cQyg63dfTS2EpguNOJzUyJGxfgfE8M5mSn0UP0pJQ
2BctMOD35Gz05UDrha3Y1LagPxdHfOKliJiULRNgjiow8WnYAs6qA7+95Hbe8OIo
lKbKQc6pCw/KAyslMXB6aGlblbHQ3X1iaVyu/tX0zCoq55qZHaJZuIM3AoGAOzfu
2671XOEWdQ213WG+8YznodJTEmBle9RrFySn95YL/W42M0G4RWOhBg0cjp3rSDrx
+Hvwm5UsU6r5yX1kRmP6ukqn2NyFXERlwwa1TaTSqHIRvqy/XbfQ4ObXSH79D/cU
uYiE0SU5/W0DQvfDnelOTJrPI7pSJMrdQ6k4qdcCgYEAtt4OP0N7rQnSe+YYONK7
959tPNYDj9ZV6cFoZus/AtRd3HEXLzXVrcxwqYCdzdoHrEsFLC2/XGYDaSadhSfr
671hnWaLNFFg5ppx7gDBmn+R7hj11ZYV1Ekt7IR9rPCXrDR97eINFSyXBby6l+qU
i8YkitP7I3fx1gQg2lVVdWQ=
-----END PRIVATE KEY-----
)EOF";

WiFiClientSecure net;
PubSubClient mqtt(net);
unsigned long lastPublish = 0;
const unsigned long PUBLISH_MS = 10000;

void connectWiFi() {
  Serial.printf("WiFi: joining %s\n", WIFI_SSID);
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
  Serial.printf("\nWiFi: ip=%s mac=%s\n",
                WiFi.localIP().toString().c_str(),
                WiFi.macAddress().c_str());
}

void syncTime() {
  configTime(0, 0, "pool.ntp.org", "time.nist.gov");
  Serial.print("NTP: syncing");
  time_t now = time(nullptr);
  int tries = 0;
  while (now < 1700000000 && tries < 40) {
    delay(500); Serial.print("."); now = time(nullptr); tries++;
  }
  Serial.printf("\nNTP: epoch=%ld\n", (long)now);
}

void connectMQTT() {
  while (!mqtt.connected()) {
    Serial.print("MQTT/TLS: connecting... ");
    if (mqtt.connect(DEVICE_ID)) {
      Serial.println("ok");
      mqtt.publish("ztgw/esp32-01/status", "online", true);
    } else {
      char err[128];
      net.lastError(err, sizeof(err));
      Serial.printf("failed rc=%d tls=%s\n", mqtt.state(), err);
      delay(5000);
    }
  }
}

void setup() {
  Serial.begin(115200);
  Serial.printf("free heap: %d\n", ESP.getFreeHeap());
  delay(1000);
  Serial.println("\n=== ztgw esp32-01 (mTLS) ===");
  connectWiFi();
  syncTime();
  net.setCACert(CA_CERT);
  net.setCertificate(CLIENT_CERT);
  net.setPrivateKey(CLIENT_KEY);
  mqtt.setServer(MQTT_HOST, MQTT_PORT);
  connectMQTT();
}

void loop() {
  if (WiFi.status() != WL_CONNECTED) connectWiFi();
  if (!mqtt.connected()) connectMQTT();
  mqtt.loop();

  unsigned long now = millis();
  if (now - lastPublish >= PUBLISH_MS) {
    lastPublish = now;
    float fakeTemp = 20.0 + (millis() % 5000) / 1000.0;
    char payload[96];
    snprintf(payload, sizeof(payload),
             "{\"device\":\"%s\",\"temp_c\":%.2f,\"uptime_s\":%lu}",
             DEVICE_ID, fakeTemp, millis() / 1000);
    mqtt.publish("ztgw/esp32-01/telemetry", payload);
    Serial.printf("pub: %s\n", payload);
  }
}