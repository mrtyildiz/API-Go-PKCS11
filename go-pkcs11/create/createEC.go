package create

import (
	"encoding/asn1"
	"fmt"

	"github.com/miekg/pkcs11"
)

// getCurveOID returns the OID for a given elliptic curve name
func getCurveOID(curveName string) (asn1.ObjectIdentifier, error) {
	switch curveName {
	case "secp192r1":
		return asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 1}, nil
	case "secp224r1":
		return asn1.ObjectIdentifier{1, 3, 132, 0, 33}, nil
	case "secp256r1":
		return asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}, nil
	case "secp384r1":
		return asn1.ObjectIdentifier{1, 3, 132, 0, 34}, nil
	case "secp521r1":
		return asn1.ObjectIdentifier{1, 3, 132, 0, 35}, nil
	case "brainpoolP256r1":
		return asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 7}, nil
	default:
		return nil, fmt.Errorf("unsupported curve: %s", curveName)
	}
}

// GenerateECKeyPair generates an EC key pair on the HSM
func GenerateECKeyPair(libraryPath string, slot uint, pin string, curveName string, keyLabel string, keyID []byte) (string, error) {
	// Initialize the PKCS11 module
	p := pkcs11.New(libraryPath)
	if err := p.Initialize(); err != nil {
		return "", fmt.Errorf("failed to initialize PKCS#11 library: %v", err)
	}
	defer p.Finalize()

	// Open session
	session, err := p.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return "", fmt.Errorf("failed to open session: %v", err)
	}
	defer p.CloseSession(session)

	// Log in to the HSM
	if err := p.Login(session, pkcs11.CKU_USER, pin); err != nil {
		return "", fmt.Errorf("failed to log in: %v", err)
	}
	defer p.Logout(session)

	// Get curve OID
	oidNamedCurve, err := getCurveOID(curveName)
	if err != nil {
		return "", fmt.Errorf("error selecting curve OID: %v", err)
	}

	// Encode the curve parameters
	ecParams, err := asn1.Marshal(oidNamedCurve)
	if err != nil {
		return "", fmt.Errorf("failed to encode EC parameters: %v", err)
	}

	// Define EC key attributes
	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel+"_pub"),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParams),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
	}

	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel+"_priv"),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
	}

	// Generate the EC key pair
	pubKeyHandle, privKeyHandle, err := p.GenerateKeyPair(
		session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)},
		publicKeyTemplate,
		privateKeyTemplate,
	)
	if err != nil {
		return "", fmt.Errorf("failed to generate EC key pair: %v", err)
	}

	// Return key details
	return fmt.Sprintf("EC key pair generated successfully:\nPublic Key Label: %s\nPrivate Key Label: %s\nPublic Key Handle: %v\nPrivate Key Handle: %v",
		keyLabel+"_pub", keyLabel+"_priv", pubKeyHandle, privKeyHandle), nil
}
