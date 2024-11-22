
# PKCS#11 HSM API Documentation

This project provides a RESTful API built with the GIN framework to interact with a PKCS#11-based HSM (Hardware Security Module). The API supports various cryptographic operations, including AES, RSA, and ECC key management, encryption, decryption, and certificate handling.

---

## Installation and Setup

1. **Set the Required Environment Variable**  
   Define the path to your PKCS#11 library using the `PKCS11_LIB` environment variable:
   ```bash
   export PKCS11_LIB=/path/to/your/pkcs11/library.so
   ```

2. **Install Dependencies**  
   Use the following command to download and install project dependencies:
   ```bash
   go mod tidy
   ```

3. **Run the API**  
   Start the API server:
   ```bash
   go run main.go
   ```
   The API will run on `http://localhost:8080` by default.

---

## API Endpoints

### 1. **AES Key Creation**
- **Endpoint**: `POST /create/aesCreate`
- **Description**: Creates an AES key on the HSM.
- **Request Body**:
  ```json
  {
      "slot_id": 0,
      "slot_pin": "1111",
      "key_size": 256,
      "key_label": "MyAESKey"
  }
  ```
- **Response**:
  ```json
  {
      "message": "AES key generated successfully"
  }
  ```

---

### 2. **RSA Key Creation**
- **Endpoint**: `POST /create/rsaCreate`
- **Description**: Creates an RSA key on the HSM.
- **Request Body**:
  ```json
  {
      "slot_id": 0,
      "user_pin": "1111",
      "key_size": 2048,
      "key_label": "MyRSAKey"
  }
  ```
- **Response**:
  ```json
  {
      "message": "RSA key generated successfully"
  }
  ```

---

### 3. **ECC Key Pair Creation**
- **Endpoint**: `POST /create/ecCreate`
- **Description**: Creates an ECC key pair on the HSM.
- **Request Body**:
  ```json
  {
      "slot": 0,
      "pin": "1111",
      "curve_name": "P-256",
      "key_label": "MyECKey",
      "key_id": [1, 2, 3, 4]
  }
  ```
- **Response**:
  ```json
  {
      "message": "ECC key pair generated successfully"
  }
  ```

---

### 4. **AES Encryption**
- **Endpoint**: `POST /encrypt/aesEncrypt`
- **Description**: Encrypts plaintext using an AES key.
- **Request Body**:
  ```json
  {
      "slot_id": 0,
      "slot_pin": "1111",
      "key_label": "MyAESKey",
      "plain_text": "This is a secret message"
  }
  ```
- **Response**:
  ```json
  {
      "cipher_text": "HEX_ENCODED_CIPHERTEXT"
  }
  ```

---

### 5. **AES Decryption**
- **Endpoint**: `POST /encrypt/aesDecrypt`
- **Description**: Decrypts ciphertext using an AES key.
- **Request Body**:
  ```json
  {
      "slot_id": 0,
      "slot_pin": "1111",
      "key_label": "MyAESKey",
      "cipher_text": "HEX_ENCODED_CIPHERTEXT"
  }
  ```
- **Response**:
  ```json
  {
      "plain_text": "This is a secret message"
  }
  ```

---

### 6. **RSA Encryption**
- **Endpoint**: `POST /encrypt/rsaEncrypt`
- **Description**: Encrypts plaintext using an RSA key.
- **Request Body**:
  ```json
  {
      "slot": 0,
      "pin": "1111",
      "label": "MyRSAKey",
      "plaintext": "This is a secret message"
  }
  ```
- **Response**:
  ```json
  {
      "ciphertext": "BASE64_ENCODED_CIPHERTEXT"
  }
  ```

---

### 7. **RSA Decryption**
- **Endpoint**: `POST /decrypt/rsaDecrypt`
- **Description**: Decrypts ciphertext using an RSA private key.
- **Request Body**:
  ```json
  {
      "slot": 0,
      "pin": "1111",
      "label": "MyRSAKey",
      "ciphertext": "BASE64_ENCODED_CIPHERTEXT"
  }
  ```
- **Response**:
  ```json
  {
      "plaintext": "This is a secret message"
  }
  ```

---

### 8. **Certificate Upload**
- **Endpoint**: `POST /upload`
- **Description**: Uploads a certificate file to the HSM.
- **Form Data**:
  - `file`: Certificate file (`.cer` or `.crt`)
  - `slotID`: HSM Slot ID (e.g., `0`)
  - `slotPIN`: HSM PIN (e.g., `1111`)
  - `CertificateName`: Name for the certificate
- **Response**:
  ```json
  {
      "message": "File uploaded successfully",
      "file": "cert.crt",
      "path": "/uploads/cert.crt"
  }
  ```

---

### 9. **DES3 Key Creation**
- **Endpoint**: `POST /create/desCreate`
- **Description**: Creates a DES3 key on the HSM.
- **Request Body**:
  ```json
  {
      "slot": 0,
      "pin": "1111",
      "keyLabel": "MyDES3Key",
      "keyID": [1, 2, 3, 4]
  }
  ```
- **Response**:
  ```json
  {
      "message": "DES3 key generated successfully",
      "keyLabel": "MyDES3Key"
  }
  ```

---

### 10. **ECC Key Upload**
- **Endpoint**: `POST /import/EC-keys`
- **Description**: Imports ECC private and public keys to the HSM.
- **Form Data**:
  - `slotID`: HSM Slot ID
  - `slotPIN`: HSM PIN
  - `keyLabel`: Key label
  - `privateKey`: ECC private key file
  - `publicKey`: ECC public key file
- **Response**:
  ```json
  {
      "message": "Keys imported successfully"
  }
  ```

---

### 11. **Remove Object**
- **Endpoint**: `POST /remove/obje`
- **Description**: Removes an object from the HSM by its label.
- **Request Body**:
  ```json
  {
      "slot_id": 0,
      "slot_pin": "1111",
      "key_label": "MyKeyLabel"
  }
  ```
- **Response**:
  ```json
  {
      "message": "Key deleted successfully"
  }
  ```

---

## Error Responses
In case of errors, the API will return a JSON object with the error message:
```json
{
    "error": "Detailed error message"
}
```

---

## Development Notes
- **Dependencies**:
  - `github.com/gin-gonic/gin`: GIN framework for building APIs.
  - `github.com/miekg/pkcs11`: Go library for PKCS#11 integration.

- **Directory Structure**:
  - `certificate/`: Certificate-related functions.
  - `create/`: Key creation functions.
  - `encrypt/`: Encryption and decryption functions.
  - `remove/`: Object removal functions.

This API provides a robust interface for secure cryptographic operations using a PKCS#11-compatible HSM. Each endpoint is designed to accept dynamic inputs for flexibility and customization.

