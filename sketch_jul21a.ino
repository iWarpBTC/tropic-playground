// Arduino jako SPI proxy pro TROPIC01
// Komunikuje s PC/Pythonem pres UART a s TROPIC01 pres SPI

#include <SPI.h>

#define CS_PIN 10

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
    digitalWrite(CS_PIN, LOW);
    uint8_t status = SPI.transfer(0xAA); // ping čip

    if (status & 0x01)
      return true;
  }
  digitalWrite(CS_PIN, HIGH);
  return false;
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
  static bool sent = false;
  if (!sent)
  {
    sent = true;

    // Ručně připrav L2 Get_Info_Req (0x01 0x02 0x01 0x00 + CRC)
    uint8_t test_frame[6] = {0x01, 0x02, 0x01, 0x00, 0x2B, 0x92};

    // Pošli L2 požadavek
    digitalWrite(CS_PIN, LOW);
    for (int i = 0; i < 6; i++)
    {
      SPI.transfer(test_frame[i]);
    }
    digitalWrite(CS_PIN, HIGH);

    // Počkej na odpověď
    if (!wait_for_ready())
    {
      Serial.println(F("❌ TROPIC01 neodpovídá"));
      return;
    }

    // Čti odpověď
    digitalWrite(CS_PIN, LOW);
    uint8_t status = SPI.transfer(0x00);
    uint8_t length = SPI.transfer(0x00);
    Serial.print(F("📥 STATUS: 0x"));
    Serial.println(status, HEX);
    Serial.print(F("📥 LENGTH: "));
    Serial.println(length);

    for (int i = 0; i < length + 2; i++)
    {
      spi_rx[i] = SPI.transfer(0x00);
    }
    digitalWrite(CS_PIN, HIGH);

    Serial.print(F("📥 DATA+CRC: "));
    for (int i = 0; i < length + 2; i++)
    {
      Serial.print(spi_rx[i], HEX);
      Serial.print(" ");
    }
    Serial.println();

    delay(60000); // počkej 60 sekund než čteš odpověď
    return;
  }

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
  digitalWrite(CS_PIN, LOW);
  for (uint8_t i = 0; i < len; i++)
  {
    SPI.transfer(spi_tx[i]);
  }
  digitalWrite(CS_PIN, HIGH);

  // Pošli opakovaně Get_Response (0x00) dokud není připraven
  if (!wait_for_ready())
    return;

  digitalWrite(CS_PIN, LOW);
  uint8_t status = SPI.transfer(0x00);
  uint8_t length = SPI.transfer(0x00);
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
}