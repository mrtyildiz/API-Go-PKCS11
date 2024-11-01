package create

import (
	"fmt"
	"log"
	"os"
	"github.com/miekg/pkcs11"
)

// GenerateAESKey PKCS#11 ile bir AES anahtarı oluşturur ve geri döner.
func GenerateAESKey(slotID int, userPin string, keySize int, keyLabel string) error {
	// PKCS#11 kütüphanesinin yolu
	libPath := os.Getenv("PKCS11_LIB")

	// PKCS#11 kütüphanesini başlat
	p := pkcs11.New(libPath)
	err := p.Initialize()
	if err != nil {
		log.Fatalf("PKCS#11 başlatılamadı: %v", err)
		return err
	}
	defer p.Finalize()

	// Oturum aç ve giriş yap
	session, err := p.OpenSession(uint(slotID), pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		log.Fatalf("Oturum açılamadı: %v", err)
		return err
	}
	defer p.CloseSession(session)

	err = p.Login(session, pkcs11.CKU_USER, userPin)
	if err != nil {
		log.Fatalf("Giriş yapılamadı: %v", err)
		return err
	}
	defer p.Logout(session)

	// AES anahtarı oluşturma işlemi
	keyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, keySize/8), // Byte'a çevirmek için keySize / 8
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true), // HSM içinde kalıcı olması için
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel), // Anahtar etiketi
	}

	aesKey, err := p.GenerateKey(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)}, keyTemplate)
	if err != nil {
		log.Fatalf("AES anahtarı oluşturulamadı: %v", err)
		return err
	}

	fmt.Printf("AES anahtarı oluşturuldu: %v\n", aesKey)
	return nil
}
