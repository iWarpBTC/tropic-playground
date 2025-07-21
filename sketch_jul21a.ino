// Arduino jako SPI proxy pro TROPIC01
// Komunikuje s PC/Pythonem pres UART a s TROPIC01 pres SPI

#include <SPI.h>

#define START_BYTE_IN 0xA5  // Z PC do Arduina
#define START_BYTE_OUT 0x5A // Z Arduina do PC
#define MAX_LEN 256

uint8_t spi_rx[MAX_LEN];
uint8_t spi_tx[MAX_LEN];

bool wait_for_ready()
{
  for (int i = 0; i < 50; i++)
  {
    delay(10);
    digitalWrite(SS, LOW);
    uint8_t status = SPI.transfer(0xAA); // ping čip
    digitalWrite(SS, HIGH);

    if (status & 0x01)
      return true;
  }
  return false;
}

void setup()
{
  Serial.begin(115200);
  SPI.begin();
  pinMode(SS, OUTPUT);
  digitalWrite(SS, HIGH); // SPI neaktivni
}

void loop()
{
  if (Serial.available() < 2)
    return;

  if (Serial.read() != START_BYTE_IN)
    return;
  uint8_t len = Serial.read();
  if (len == 0 || len > MAX_LEN)
    return;

  // Nacti SPI payload od PC
  while (Serial.available() < len)
    ;
  Serial.readBytes(spi_tx, len);

  // SPI komunikace – pošli L2 požadavek
  digitalWrite(SS, LOW);
  for (uint8_t i = 0; i < len; i++)
  {
    SPI.transfer(spi_tx[i]);
  }
  digitalWrite(SS, HIGH);

  // Pošli opakovaně Get_Response (0x00) dokud není připraven
  if (!wait_for_ready())
    return;

  digitalWrite(SS, LOW);
  uint8_t status = SPI.transfer(0x00);
  uint8_t length = SPI.transfer(0x00);
  if (length + 2 > MAX_LEN)
  {
    digitalWrite(SS, HIGH);
    return;
  }

  for (uint8_t i = 0; i < length + 2; i++)
  {
    spi_rx[i] = SPI.transfer(0x00);
  }
  digitalWrite(SS, HIGH);

  // Pošli odpověď zpět na PC
  Serial.write(START_BYTE_OUT);
  Serial.write(length + 4); // STATUS + LENGTH + PAYLOAD + CRC (2B)
  Serial.write(status);
  Serial.write(length);
  Serial.write(spi_rx, length + 2);
}