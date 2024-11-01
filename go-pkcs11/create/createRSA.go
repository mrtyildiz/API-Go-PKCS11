package create

import (
	"fmt"
	"os"

	"github.com/miekg/pkcs11"
)

// GenerateRSAKey generates an RSA key on the HSM
func GenerateRSAKey(slotID int, userPin string, keySize int, keyLabel string) (string, error) {
	libraryPath := os.Getenv("PKCS11_LIB")
	if libraryPath == "" {
		return "", fmt.Errorf("PKCS11_LIB environment variable is not set")
	}

	p := pkcs11.New(libraryPath)
	if err := p.Initialize(); err != nil {
		return "", fmt.Errorf("failed to initialize PKCS#11 library: %v", err)
	}
	defer p.Finalize()

	// Belirtilen slot numarası ile oturumu başlatıyoruz
	session, err := p.OpenSession(uint(slotID), pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return "", fmt.Errorf("failed to open session: %v", err)
	}
	defer p.CloseSession(session)

	// Belirtilen PIN ile oturumu açıyoruz
	if err := p.Login(session, pkcs11.CKU_USER, userPin); err != nil {
		return "", fmt.Errorf("failed to log in: %v", err)
	}
	defer p.Logout(session)

	modulusBits := keySize
	keyID := []byte{1, 2, 3, 4}

	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel+"_pub"),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, modulusBits),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
	}

	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel+"_priv"),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
	}

	pubKeyHandle, privKeyHandle, err := p.GenerateKeyPair(
		session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)},
		publicKeyTemplate,
		privateKeyTemplate,
	)
	if err != nil {
		return "", fmt.Errorf("failed to generate RSA key pair: %v", err)
	}

	return fmt.Sprintf("RSA key pair generated on HSM with labels:\nPublic Key Label: %s\nPrivate Key Label: %s\nPublic Key Handle: %v\nPrivate Key Handle: %v", keyLabel+"_pub", keyLabel+"_priv", pubKeyHandle, privKeyHandle), nil
}