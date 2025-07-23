// Arduino jako SPI proxy pro TROPIC01
// Komunikuje s PC/Pythonem pres UART a s TROPIC01 pres SPI

#include <SPI.h>

#define CS_PIN 10

#define START_BYTE_IN 0xA5  // Z PC do Arduina
#define START_BYTE_OUT 0x5A // Z Arduina do PC
#define MAX_LEN 256

uint8_t spi_rx[MAX_LEN];
uint8_t spi_tx[MAX_LEN];

void send_error_resp(uint8_t status)
{
  Serial.write(START_BYTE_OUT);
  Serial.write(2); // STATUS + LENGTH
  Serial.write(status);
  Serial.write(0);
}

void setup()
{
  Serial.begin(115200);
  SPI.begin();
  pinMode(CS_PIN, OUTPUT);
  digitalWrite(CS_PIN, HIGH); // SPI neaktivni
}

void loop()
{
  // Máme v bufferu aspoň 2B?
  if (Serial.available() < 2)
    return;

  // Zkontroluj start byte a délku
  if (Serial.read() != START_BYTE_IN)
    return;
  uint8_t len = Serial.read();
  if (len > MAX_LEN)
    return;

  // Nacti SPI payload od PC
  while (Serial.available() < len)
    ;
  Serial.readBytes(spi_tx, len);

  // SPI komunikace – pošli L2 požadavek
  digitalWrite(CS_PIN, LOW);
  for (uint8_t i = 0; i < len; i++)
  {
    SPI.transfer(spi_tx[i]);
  }
  digitalWrite(CS_PIN, HIGH);

  // Pošli opakovaně Get_Response (0x00) dokud není připraven
  for (int i = 0; i < 50; i++)
  {
    digitalWrite(CS_PIN, LOW);
    uint8_t chip_status = SPI.transfer(0xAA);

    if (chip_status & 0x04) // START
    {
      send_error_resp(0xB4); // ERROR_START
      digitalWrite(CS_PIN, HIGH);
      return;
    }

    if (chip_status & 0x02) // ALARM
    {
      send_error_resp(0xB2); // ERROR_START
      digitalWrite(CS_PIN, HIGH);
      return;
    }

    if (chip_status & 0x01) // READY
    {
      uint8_t status = SPI.transfer(0x00);
      uint8_t length = SPI.transfer(0x00);

      if (status == 0xFF)
      {
        digitalWrite(CS_PIN, HIGH);
        delay(25);
        continue;
      }

      if (length + 2 > MAX_LEN)
      {
        digitalWrite(CS_PIN, HIGH);
        return;
      }

      for (uint8_t i = 0; i < length + 2; i++)
      {
        spi_rx[i] = SPI.transfer(0x00);
      }
      digitalWrite(CS_PIN, HIGH);

      // Pošli odpověď zpět na PC
      Serial.write(START_BYTE_OUT);
      Serial.write(length + 4); // STATUS + LENGTH + PAYLOAD + CRC (2B)
      Serial.write(status);
      Serial.write(length);
      Serial.write(spi_rx, length + 2);

      return;
    }

    digitalWrite(CS_PIN, HIGH);
    delay(25);
  }
}