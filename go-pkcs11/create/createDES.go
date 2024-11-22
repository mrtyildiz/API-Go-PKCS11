package create

import (
	"fmt"

	"github.com/miekg/pkcs11"
)

type HSMManager struct {
	LibraryPath string
	PKCS11      *pkcs11.Ctx
	Session     pkcs11.SessionHandle
	Slot        uint
}

// NewHSMManager initializes a new HSM manager
func NewHSMManager(libraryPath string, slot uint) (*HSMManager, error) {
	p := pkcs11.New(libraryPath)
	if err := p.Initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize PKCS#11 library: %v", err)
	}

	return &HSMManager{
		LibraryPath: libraryPath,
		PKCS11:      p,
		Slot:        slot,
	}, nil
}

// Login logs in to the HSM
func (h *HSMManager) Login(pin string) error {
	session, err := h.PKCS11.OpenSession(h.Slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return fmt.Errorf("failed to open session: %v", err)
	}
	h.Session = session

	if err := h.PKCS11.Login(h.Session, pkcs11.CKU_USER, pin); err != nil {
		return fmt.Errorf("failed to log in: %v", err)
	}
	return nil
}

// Logout logs out and closes the session
func (h *HSMManager) Logout() {
	if h.Session != 0 {
		h.PKCS11.Logout(h.Session)
		h.PKCS11.CloseSession(h.Session)
		h.Session = 0
	}
}

// Finalize finalizes the PKCS#11 library
func (h *HSMManager) Finalize() {
	h.PKCS11.Finalize()
}

// GenerateDES3Key generates a DES3 key on the HSM
func (h *HSMManager) GenerateDES3Key(keyLabel string, keyID []byte) (pkcs11.ObjectHandle, error) {
	des3KeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_DES3),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
	}

	keyHandle, err := h.PKCS11.GenerateKey(
		h.Session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_DES3_KEY_GEN, nil)},
		des3KeyTemplate,
	)
	if err != nil {
		return 0, fmt.Errorf("failed to generate DES3 key: %v", err)
	}

	return keyHandle, nil
}
