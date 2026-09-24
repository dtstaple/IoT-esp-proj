#include <WiFi.h>
#include <PubSubClient.h>

const char* WIFI_SSID = "ZT-IOT";
const char* WIFI_PASS = "ztgateway2026";
const char* MQTT_HOST = "10.42.0.1";
const int   MQTT_PORT = 1883;
const char* DEVICE_ID = "esp32-01";

WiFiClient net;
PubSubClient mqtt(net);

unsigned long lastPublish = 0;
const unsigned long PUBLISH_MS = 10000;

void connectWiFi() {
  Serial.printf("WiFi: joining %s\n", WIFI_SSID);
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.printf("\nWiFi: connected, ip=%s mac=%s\n",
                WiFi.localIP().toString().c_str(),
                WiFi.macAddress().c_str());
}

void connectMQTT() {
  while (!mqtt.connected()) {
    Serial.print("MQTT: connecting... ");
    if (mqtt.connect(DEVICE_ID)) {
      Serial.println("ok");
      mqtt.publish("ztgw/esp32-01/status", "online", true);
    } else {
      Serial.printf("failed rc=%d, retry in 3s\n", mqtt.state());
      delay(3000);
    }
  }
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  Serial.println("\n=== ztgw esp32-01 ===");
  connectWiFi();
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