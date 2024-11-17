## API Entpoint
### Anahtar Yönetimi

#### AES Anahtar Oluşturma

- **Endpoint**: `/create/aesCreate`
- **HTTP Method**: `POST`
- **Request Payload**:

  ```json
  {
    "slot_id": 0,
    "slot_pin": "1234",
    "key_size": 256,
    "key_label": "MyAESKey"
  }
  ```

- **Response**:
  - `200 OK`: `{"message": "AES key generated successfully"}`
  - `500 Internal Server Error`: `{ "error": "Failed to generate AES key" }`

#### RSA Anahtar Oluşturma

- **Endpoint**: `/create/rsaCreate`
- **HTTP Method**: `POST`
- **Request Payload**:

  ```json
  {
    "slot_id": 0,
    "user_pin": "1234",
    "key_size": 2048,
    "key_label": "MyRSAKey"
  }
  ```

- **Response**:
  - `200 OK`: `{"message": "RSA key created successfully"}`
  - `500 Internal Server Error`: `{ "error": "Failed to generate RSA key" }`

### Şifreleme ve Çözme

#### AES Şifreleme

- **Endpoint**: `/encrypt/aesEncrypt`
- **HTTP Method**: `POST`
- **Request Payload**:

  ```json
  {
    "slot_id": 0,
    "slot_pin": "1234",
    "key_label": "MyAESKey",
    "plain_text": "Hello, World!"
  }
  ```

- **Response**:
  - `200 OK`: `{ "cipher_text": "<hexadecimal_ciphertext>" }`
  - `500 Internal Server Error`: `{ "error": "Encryption failed" }`

#### AES Çözme

- **Endpoint**: `/encrypt/aesDecrypt`
- **HTTP Method**: `POST`
- **Request Payload**:

  ```json
  {
    "slot_id": 0,
    "slot_pin": "1234",
    "key_label": "MyAESKey",
    "cipher_text": "<hexadecimal_ciphertext>"
  }
  ```

- **Response**:
  - `200 OK`: `{ "plain_text": "Hello, World!" }`
  - `500 Internal Server Error`: `{ "error": "Decryption failed" }`

#### AES-CBC Şifreleme

- **Endpoint**: `/encrypt/aesCBCEncrypt`
- **HTTP Method**: `POST`
- **Request Payload**:

  ```json
  {
    "slot_id": 0,
    "slot_pin": "1234",
    "key_label": "MyAESKey",
    "plain_text": "Hello, World!",
    "iv": "<hexadecimal_initialization_vector>"
  }
  ```

- **Response**:
  - `200 OK`: `{ "cipher_text": "<hexadecimal_ciphertext>" }`
  - `500 Internal Server Error`: `{ "error": "Encryption failed" }`

#### AES-CBC Çözme

- **Endpoint**: `/decrypt/aesCBCDecrypt`
- **HTTP Method**: `POST`
- **Request Payload**:

  ```json
  {
    "slot_id": 0,
    "slot_pin": "1234",
    "key_label": "MyAESKey",
    "cipher_text": "<hexadecimal_ciphertext>",
    "iv": "<hexadecimal_initialization_vector>"
  }
  ```

- **Response**:
  - `200 OK`: `{ "plain_text": "Hello, World!" }`
  - `500 Internal Server Error`: `{ "error": "Decryption failed" }`

