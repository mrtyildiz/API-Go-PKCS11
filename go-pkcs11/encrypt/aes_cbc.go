package encrypt

import (
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"bytes"
	"fmt"
	"encoding/hex"
	"github.com/miekg/pkcs11"
)

// InitializePKCS11 initializes the PKCS#11 library, opens a session, and logs in to the HSM.
func InitializePKCS11(libraryPath, pin string, slot uint) (*pkcs11.Ctx, pkcs11.SessionHandle, error) {
	p := pkcs11.New(libraryPath)
	if err := p.Initialize(); err != nil {
		return nil, 0, fmt.Errorf("failed to initialize PKCS#11 library: %v", err)
	}

	session, err := p.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		p.Finalize()
		return nil, 0, fmt.Errorf("failed to open session: %v", err)
	}

	if err := p.Login(session, pkcs11.CKU_USER, pin); err != nil {
		p.CloseSession(session)
		p.Finalize()
		return nil, 0, fmt.Errorf("failed to log in: %v", err)
	}

	return p, session, nil
}

// FindAESKey locates an AES key in the HSM by label.
func FindAESKey(p *pkcs11.Ctx, session pkcs11.SessionHandle, label string) (pkcs11.ObjectHandle, error) {
	err := p.FindObjectsInit(session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
	})
	if err != nil {
		return 0, fmt.Errorf("failed to initialize search for key: %v", err)
	}

	handles, _, err := p.FindObjects(session, 1)
	if err != nil {
		p.FindObjectsFinal(session)
		return 0, fmt.Errorf("failed to find objects: %v", err)
	}

	err = p.FindObjectsFinal(session)
	if err != nil {
		return 0, fmt.Errorf("failed to finalize object search: %v", err)
	}

	if len(handles) == 0 {
		return 0, fmt.Errorf("no AES key found with label: %s", label)
	}

	return handles[0], nil
}

// Pad adds PKCS#7 padding to plaintext.
func Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

// Unpad removes PKCS#7 padding from plaintext.
func Unpad(data []byte) ([]byte, error) {
	length := len(data)
	unpadding := int(data[length-1])
	return data[:(length - unpadding)], nil
}

// EncryptData encrypts plaintext using AES in ECB mode.
func EncryptData(p *pkcs11.Ctx, session pkcs11.SessionHandle, aesKey pkcs11.ObjectHandle, plaintext []byte) ([]byte, error) {
	plaintext = Pad(plaintext, 16) // AES block size is 16 bytes

	err := p.EncryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_ECB, nil)}, aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize encryption: %v", err)
	}

	ciphertext, err := p.Encrypt(session, plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data: %v", err)
	}

	return ciphertext, nil
}

// DecryptData decrypts ciphertext using AES in ECB mode.
func DecryptData(p *pkcs11.Ctx, session pkcs11.SessionHandle, aesKey pkcs11.ObjectHandle, ciphertext []byte) ([]byte, error) {
	err := p.DecryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_ECB, nil)}, aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize decryption: %v", err)
	}

	plaintext, err := p.Decrypt(session, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %v", err)
	}

	plaintext, err = Unpad(plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to unpad data: %v", err)
	}

	return plaintext, nil
}

// EncryptCBC encrypts plaintext using AES in CBC mode with a user-provided IV.
func EncryptCBC(p *pkcs11.Ctx, session pkcs11.SessionHandle, aesKey pkcs11.ObjectHandle, plaintext []byte, ivHex string) ([]byte, error) {
	// Pad plaintext to be a multiple of AES block size (16 bytes)
	plaintext = Pad(plaintext, 16)

	// Decode the provided IV from hexadecimal string
	iv, err := hex.DecodeString(ivHex)
	if err != nil {
		return nil, fmt.Errorf("invalid IV format: %v", err)
	}
	if len(iv) != 16 {
		return nil, fmt.Errorf("IV must be 16 bytes long")
	}

	// Initialize encryption with CBC mode
	err = p.EncryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_CBC_PAD, iv)}, aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize encryption: %v", err)
	}

	ciphertext, err := p.Encrypt(session, plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data: %v", err)
	}

	return ciphertext, nil
}

// DecryptCBC decrypts ciphertext using AES in CBC mode with a user-provided IV.
func DecryptCBC(p *pkcs11.Ctx, session pkcs11.SessionHandle, aesKey pkcs11.ObjectHandle, ciphertext []byte, ivHex string) ([]byte, error) {
	// Decode the provided IV from hexadecimal string
	iv, err := hex.DecodeString(ivHex)
	if err != nil {
		return nil, fmt.Errorf("invalid IV format: %v", err)
	}
	if len(iv) != 16 {
		return nil, fmt.Errorf("IV must be 16 bytes long")
	}

	// Initialize decryption with the same IV used for encryption
	err = p.DecryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_CBC_PAD, iv)}, aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize decryption: %v", err)
	}

	plaintext, err := p.Decrypt(session, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %v", err)
	}

	// Remove padding after decryption
	plaintext, err = Unpad(plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to unpad data: %v", err)
	}

	return plaintext, nil
}

// FindRSAKey finds an RSA private key on HSM and retrieves its public counterpart
func FindRSAKey(p *pkcs11.Ctx, session pkcs11.SessionHandle, label string) (pkcs11.ObjectHandle, *rsa.PublicKey, error) {
	err := p.FindObjectsInit(session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
	})
	if err != nil {
		return 0, nil, fmt.Errorf("failed to initialize search for key: %v", err)
	}

	handles, _, err := p.FindObjects(session, 1)
	if err != nil {
		p.FindObjectsFinal(session)
		return 0, nil, fmt.Errorf("failed to find objects: %v", err)
	}

	err = p.FindObjectsFinal(session)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to finalize object search: %v", err)
	}

	if len(handles) == 0 {
		return 0, nil, fmt.Errorf("no RSA key found with label: %s", label)
	}

	attributes := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
	}
	attributes, err = p.GetAttributeValue(session, handles[0], attributes)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to get public key attributes: %v", err)
	}

	modulus := new(big.Int).SetBytes(attributes[0].Value)
	exponent := new(big.Int).SetBytes(attributes[1].Value).Int64()

	pubKey := &rsa.PublicKey{
		N: modulus,
		E: int(exponent),
	}

	return handles[0], pubKey, nil
}

// EncryptDataRSA encrypts data using RSA public key
func EncryptDataRSA(pubKey *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data: %v", err)
	}
	return ciphertext, nil
}

// DecryptDataRSA decrypts data using RSA private key on HSM
func DecryptDataRSA(p *pkcs11.Ctx, session pkcs11.SessionHandle, privKeyHandle pkcs11.ObjectHandle, ciphertext []byte) ([]byte, error) {
	err := p.DecryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}, privKeyHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize decryption: %v", err)
	}

	plaintext, err := p.Decrypt(session, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %v", err)
	}

	return plaintext, nil
}


