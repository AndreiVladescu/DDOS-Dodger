#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <WiFiClient.h>
#include <Crypto.h>
#include <SHA512.h>

// Replace with your network credentials
const char* ssid = "IoT-Nodes";
const char* password = "admin_iot";

// Create an instance of the server
ESP8266WebServer server(80);
SHA512 sha512;

// Function to simulate temperature reading
float getTemperature() {
  // Simulated temperature value for demonstration
  return 25.5 + random(-50, 50) / 10.0; // e.g., 24.5 to 26.5 degrees
}

String computeSHA512(String input) {
  uint8_t hash[64];
  sha512.reset();
  sha512.update((const uint8_t*)input.c_str(), input.length());
  sha512.finalize(hash, sizeof(hash));

  // Convert hash to hexadecimal string
  String hashString;
  for (int i = 0; i < 64; i++) {
    if (hash[i] < 0x10) hashString += "0";
    hashString += String(hash[i], HEX);
  }
  return hashString;
}

void handleTemperature() {
  float temperature = getTemperature();
  String tempString = String(temperature);

  // Generate SHA512 hash of the temperature string
  String hash = computeSHA512(tempString);

  // Create JSON response
  String response = "{\"temperature\": " + tempString + ", \"hash\": \"" + hash + "\"}";

  // Send response
  server.send(200, "application/json", response);
}

void setup() {
  Serial.begin(115200);
  delay(10);

  // Connect to Wi-Fi
  Serial.println();
  Serial.println("Connecting to Wi-Fi...");
  WiFi.begin(ssid, password);

  while (WiFi.status() != WL_CONNECTED) {
    delay(1000);
    Serial.print(".");
  }

  Serial.println();
  Serial.println("Wi-Fi connected.");
  Serial.print("IP address: ");
  Serial.println(WiFi.localIP());

  // Set up route
  server.on("/", handleTemperature);

  // Start server
  server.begin();
  Serial.println("HTTP server started.");
}

void loop() {
  server.handleClient();
}
