package main

import (
	"encoding/asn1"
	"fmt"
	"log"
	"os"

	"github.com/miekg/pkcs11"
)

// getCurveOID returns the OID for a given elliptic curve name
func getCurveOID(curveName string) (asn1.ObjectIdentifier, error) {
	var oidNamedCurve asn1.ObjectIdentifier

	if curveName == "secp192r1" {
		oidNamedCurve = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 1}
	} else if curveName == "secp224r1" {
		oidNamedCurve = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	} else if curveName == "secp256r1" {
		oidNamedCurve = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	} else if curveName == "secp384r1" {
		oidNamedCurve = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	} else if curveName == "secp521r1" {
		oidNamedCurve = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
	} else if curveName == "brainpoolP256r1" {
		oidNamedCurve = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 7}
	} else {
		return nil, fmt.Errorf("unsupported curve: %s", curveName)
	}

	return oidNamedCurve, nil
}

func main() {
	// Set PKCS11 library path from the environment variable
	libraryPath := os.Getenv("PKCS11_LIB")
	if libraryPath == "" {
		log.Fatal("PKCS11_LIB environment variable is not set")
	}

	// Initialize the PKCS11 module
	p := pkcs11.New(libraryPath)
	if err := p.Initialize(); err != nil {
		log.Fatalf("Failed to initialize PKCS#11 library: %v", err)
	}
	defer p.Finalize()

	// Define the slot, PIN, and EC key attributes
	slot := uint(0)
	pin := "1111"
	keyLabel := "ent_key"
	keyID := []byte{1, 2, 3, 4} // Unique ID for the key

	// Open session in slot 0
	session, err := p.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		log.Fatalf("Failed to open session: %v", err)
	}
	defer p.CloseSession(session)

	// Log in to the HSM
	if err := p.Login(session, pkcs11.CKU_USER, pin); err != nil {
		log.Fatalf("Failed to log in: %v", err)
	}
	defer p.Logout(session)

	// Select the curve
	curveName := "secp256r1" // Specify your curve here
	oidNamedCurve, err := getCurveOID(curveName)
	if err != nil {
		log.Fatalf("Error selecting curve OID: %v", err)
	}

	// Encode the curve parameters
	ecParams, err := asn1.Marshal(oidNamedCurve)
	if err != nil {
		log.Fatalf("Failed to encode EC parameters: %v", err)
	}

	// Define EC key attributes for public and private keys with persistence
	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel+"_pub"),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParams),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true), // Make key persistent on HSM
	}

	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel+"_priv"),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true), // Make key persistent on HSM
	}

	// Generate the EC key pair on the HSM
	pubKeyHandle, privKeyHandle, err := p.GenerateKeyPair(
		session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)},
		publicKeyTemplate,
		privateKeyTemplate,
	)
	if err != nil {
		log.Fatalf("Failed to generate EC key pair: %v", err)
	}

	fmt.Println("EC key pair generated on HSM with labels:")
	fmt.Printf("Public Key Label: %s\n", keyLabel+"_pub")
	fmt.Printf("Private Key Label: %s\n", keyLabel+"_priv")
	fmt.Printf("Public Key Handle: %v\n", pubKeyHandle)
	fmt.Printf("Private Key Handle: %v\n", privKeyHandle)
}
