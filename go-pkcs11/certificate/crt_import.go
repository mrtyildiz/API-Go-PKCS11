package certificate

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"

	"github.com/miekg/pkcs11"
)

// InitializePKCS11 initializes the PKCS#11 library and logs in
func InitializePKCS11(libraryPath, pin string, slot uint) (*pkcs11.Ctx, pkcs11.SessionHandle, error) {
	p := pkcs11.New(libraryPath)
	if err := p.Initialize(); err != nil {
		return nil, 0, fmt.Errorf("failed to initialize PKCS#11 library: %v", err)
	}

	// Open session
	session, err := p.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		p.Finalize()
		return nil, 0, fmt.Errorf("failed to open session: %v", err)
	}

	// Log in
	if err := p.Login(session, pkcs11.CKU_USER, pin); err != nil {
		p.CloseSession(session)
		p.Finalize()
		return nil, 0, fmt.Errorf("failed to log in: %v", err)
	}

	return p, session, nil
}

// LoadCertificateFromFile loads a PEM-encoded certificate from a file
func LoadCertificateFromFile(filename string) ([]byte, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %v", filename, err)
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode PEM block containing certificate")
	}

	// Parse the certificate to verify it's valid
	_, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	return block.Bytes, nil
}

// ImportCertificateToHSM imports a certificate into the HSM
func ImportCertificateToHSM(p *pkcs11.Ctx, session pkcs11.SessionHandle, certData []byte, label string) error {
	// Define certificate attributes
	certTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKC_X_509),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, certData), // Add subject if required
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, certData),   // The certificate content
	}

	// Create certificate object on the HSM
	_, err := p.CreateObject(session, certTemplate)
	if err != nil {
		return fmt.Errorf("failed to import certificate: %v", err)
	}

	fmt.Println("Certificate imported successfully to HSM")
	return nil
}