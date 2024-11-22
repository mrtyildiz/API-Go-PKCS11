// /go-pkcs11/main.go
package main

import (
	"encoding/base64"
	"encoding/hex"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"go-pkcs11/certificate"
	"go-pkcs11/create"
	"go-pkcs11/encrypt"
	"go-pkcs11/remove"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"github.com/gin-gonic/gin"
	"github.com/miekg/pkcs11"
)

type AES_Create struct {
	SlotID   int    `json:"slot_id"`  // binding: "required" kaldırıldı
	SlotPIN  string `json:"slot_pin" binding:"required"`
	KeySize  int    `json:"key_size" binding:"required"`
	KeyLabel string `json:"key_label" binding:"required"`
}

type KeyRSARequest struct {
	SlotID   int   `json:"slot_id"`
	UserPin  string `json:"user_pin" binding:"required"`
	KeySize  int    `json:"key_size" binding:"required"`
	KeyLabel string `json:"key_label" binding:"required"`
}


type KeyECRequest struct {
	Slot      uint   `json:"slot"`
	Pin       string `json:"pin"`
	CurveName string `json:"curve_name"`
	KeyLabel  string `json:"key_label"`
	KeyID     []byte `json:"key_id"`
}

type EncryptRequest struct {
	Slot      uint   `json:"slot_id"`       // HSM Slot ID
	Pin       string `json:"slot_pin" binding:"required"`        // HSM PIN
	KeyLabel  string `json:"key_label" binding:"required"`  // Anahtar Etiketi
	PlainText string `json:"plain_text" binding:"required"` // Şifrelenecek Metin
}

type DecryptRequest struct {
	Slot       uint   `json:"slot_id"`       // HSM Slot ID
	Pin        string `json:"slot_pin" binding:"required"`        // HSM PIN
	KeyLabel   string `json:"key_label" binding:"required"`  // Anahtar Etiketi
	CipherText string `json:"cipher_text" binding:"required"` // Şifrelenmiş Metin (Hexadecimal)
}

type EncryptRequest_CBC struct {
	Slot      uint   `json:"slot_id"`       // HSM Slot ID
	Pin       string `json:"slot_pin" binding:"required"`        // HSM PIN
	KeyLabel  string `json:"key_label" binding:"required"`  // AES Anahtar Etiketi
	PlainText string `json:"plain_text" binding:"required"` // Şifrelenecek Metin
	IV        string `json:"iv" binding:"required"`         // Kullanıcı tarafından sağlanan IV (hexadecimal)
}

type DecryptRequest_CBC struct {
	Slot       uint   `json:"slot_id"`       // HSM Slot ID
	Pin        string `json:"slot_pin" binding:"required"`         // HSM PIN
	KeyLabel   string `json:"key_label" binding:"required"`   // AES Anahtar Etiketi
	CipherText string `json:"cipher_text" binding:"required"` // Şifrelenmiş Metin (hexadecimal)
	IV         string `json:"iv" binding:"required"`          // Kullanıcı tarafından sağlanan IV (hexadecimal)
}

type aliasRequest struct {
	Slot		uint	`json:"slot_id"`
	Pin			string	`json:"slot_pin" binding:"required"`
	KeyLabel	string	`json:"key_label" binding:"required"`
}

type DESCreate struct {
	Slot     uint   `json:"slot"`
	Pin      string `json:"pin"`
	KeyLabel string `json:"keyLabel"`
	KeyID    []byte `json:"keyID"`
}


func main() {
    router := gin.Default()

    // "/hello" endpoint'ine GET isteği tanımlıyoruz
    router.POST("/create/aesCreate", func(c *gin.Context) {
		var req AES_Create

		// JSON body içeriğini doğrula
		if err := c.ShouldBindJSON(&req); err != nil {
			fmt.Printf("Hata oluştu: %v\n", err.Error())  // Hata mesajını yazdır
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// SlotID'nin manuel kontrolü
		if req.SlotID < 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "SlotID cannot be negative"})
			return
		}

		// Gelen verileri log'a yazdırıyoruz
		fmt.Printf("Received Request: SlotID: %d, SlotPIN: %s, KeySize: %d, KeyLabel: %s\n", req.SlotID, req.SlotPIN, req.KeySize, req.KeyLabel)

		// // AES anahtarını oluştur
		err := create.GenerateAESKey(req.SlotID, req.SlotPIN, req.KeySize, req.KeyLabel)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate AES key"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "AES key generated successfully"})
	})

	    	// POST endpoint for key generation
	router.POST("/create/rsaCreate", func(c *gin.Context) {
		var req KeyRSARequest

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// RSA anahtar oluşturma
		fmt.Println(req.SlotID)
		result, err := create.GenerateRSAKey(req.SlotID, req.UserPin, req.KeySize, req.KeyLabel)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": result})
	})
	
	router.POST("/create/ecCreate", func(c *gin.Context) {
		var req KeyECRequest

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		libraryPath := os.Getenv("PKCS11_LIB")
		if libraryPath == "" {
			log.Fatal("PKCS11_LIB environment variable is not set")
		}
		// Generate the EC key pair
		result, err := create.GenerateECKeyPair(libraryPath, req.Slot, req.Pin, req.CurveName, req.KeyLabel, req.KeyID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Respond with success
		c.JSON(http.StatusOK, gin.H{"message": result})
	})


		// AES Encryption Route
	router.POST("/encrypt/aesEncrypt", func(c *gin.Context) {
		var req EncryptRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// PKCS#11 Kütüphane Yolunu Al
		libraryPath := os.Getenv("PKCS11_LIB") // Replace with the correct path

		// HSM ve Oturum Başlat
		p, session, err := encrypt.InitializePKCS11(libraryPath, req.Pin, req.Slot)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		defer func() {
			p.Logout(session)
			p.CloseSession(session)
			p.Finalize()
		}()

		// AES Anahtarını Bul
		aesKey, err := encrypt.FindAESKey(p, session, req.KeyLabel)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Şifreleme İşlemi
		ciphertext, err := encrypt.EncryptData(p, session, aesKey, []byte(req.PlainText))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Hexadecimal Olarak Şifreli Veriyi Döndür
		c.JSON(http.StatusOK, gin.H{"cipher_text": hex.EncodeToString(ciphertext)})
	})


		// AES Decryption Route
	router.POST("/encrypt/aesDecrypt", func(c *gin.Context) {
		var req DecryptRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// PKCS#11 Kütüphane Yolunu Al
		libraryPath := os.Getenv("PKCS11_LIB") // Replace with the correct path

		// HSM ve Oturum Başlat
		p, session, err := encrypt.InitializePKCS11(libraryPath, req.Pin, req.Slot)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		defer func() {
			p.Logout(session)
			p.CloseSession(session)
			p.Finalize()
		}()

		// AES Anahtarını Bul
		aesKey, err := encrypt.FindAESKey(p, session, req.KeyLabel)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Şifrelenmiş Veriyi Decode Et (Hexadecimal'den Binary'ye)
		ciphertext, err := hex.DecodeString(req.CipherText)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid cipher_text format"})
			return
		}

		// Çözme İşlemi
		plaintext, err := encrypt.DecryptData(p, session, aesKey, ciphertext)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Orijinal Metni Döndür
		c.JSON(http.StatusOK, gin.H{"plain_text": string(plaintext)})
	})


	// AES-CBC Şifreleme Endpoint
	router.POST("/encrypt/aesCBCEncrypt", func(c *gin.Context) {
		var req EncryptRequest_CBC
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// PKCS#11 Kütüphane Yolunu Al
		libraryPath := os.Getenv("PKCS11_LIB")
		if libraryPath == "" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "PKCS11_LIB environment variable is not set"})
			return
		}

		// HSM ve Oturum Başlat
		p, session, err := encrypt.InitializePKCS11(libraryPath, req.Pin, req.Slot)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		defer func() {
			p.Logout(session)
			p.CloseSession(session)
			p.Finalize()
		}()

		// AES Anahtarını Bul
		aesKey, err := encrypt.FindAESKey(p, session, req.KeyLabel)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Şifreleme İşlemi
		ciphertext, err := encrypt.EncryptCBC(p, session, aesKey, []byte(req.PlainText), req.IV)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Şifreli Veriyi Hexadecimal Formatında Döndür
		c.JSON(http.StatusOK, gin.H{"cipher_text": hex.EncodeToString(ciphertext)})
	})

	// AES-CBC Çözme Endpoint
	router.POST("/decrypt/aesCBCDecrypt", func(c *gin.Context) {

		var req DecryptRequest_CBC
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// PKCS#11 Kütüphane Yolunu Al
		libraryPath := os.Getenv("PKCS11_LIB")
		if libraryPath == "" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "PKCS11_LIB environment variable is not set"})
			return
		}

		// HSM ve Oturum Başlat
		p, session, err := encrypt.InitializePKCS11(libraryPath, req.Pin, req.Slot)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		defer func() {
			p.Logout(session)
			p.CloseSession(session)
			p.Finalize()
		}()

		// AES Anahtarını Bul
		aesKey, err := encrypt.FindAESKey(p, session, req.KeyLabel)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Şifrelenmiş Metni Decode Et
		ciphertext, err := hex.DecodeString(req.CipherText)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid cipher_text format"})
			return
		}

		// Çözme İşlemi
		plaintext, err := encrypt.DecryptCBC(p, session, aesKey, ciphertext, req.IV)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Orijinal Metni Döndür
		c.JSON(http.StatusOK, gin.H{"plain_text": string(plaintext)})
	})

	router.POST("/remove/obje", func(c *gin.Context) {
		var req aliasRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	
		// PKCS#11 Kütüphane Yolunu Al
		libraryPath := os.Getenv("PKCS11_LIB")
		if libraryPath == "" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "PKCS11_LIB environment variable is not set"})
			return
		}
	
		// HSM ve Oturum Başlat
		p, session, err := encrypt.InitializePKCS11(libraryPath, req.Pin, req.Slot)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		defer func() {
			p.Logout(session)
			p.CloseSession(session)
			p.Finalize()
		}()
	
		// DeleteKeyByAlias için doğrudan req.KeyLabel kullanılıyor
		err = remove.DeleteKeyByAlias(p, session, req.KeyLabel)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	
		c.JSON(http.StatusOK, gin.H{"message": "Key deleted successfully"})
	})
	

	

	// Set a static file serving folder for uploaded files (optional)
	router.Static("/uploads", "./uploads")

	// Create the uploads directory if not already present
	err := createUploadsDirectory("./uploads")
	if err != nil {
		log.Fatalf("Could not create uploads directory: %v", err)
	}

	// Define a POST route for file upload
	router.POST("/upload", func(c *gin.Context) {
		// Single file
		file, err := c.FormFile("file")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "No file is provided"})
			return
		}
				// Check file extension
		ext := strings.ToLower(filepath.Ext(file.Filename))
		if ext != ".cer" && ext != ".crt" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid file type. Only .cer and .crt files are allowed",
			})
			return
		}
		// Retrieve string data
		slotPIN := c.PostForm("slotPIN")
		if slotPIN == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "String value is required"})
			return
		}
		// Retrieve string data
		CertificateName := c.PostForm("CertificateName")
		if CertificateName == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "String value is required"})
			return
		}

		// Retrieve int data
		slotIDStr := c.PostForm("slotID")
		slotID, err := strconv.Atoi(slotIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid integer value"})
			return
		}

		
		// Destination path for the uploaded file
		dst := filepath.Join("./uploads", filepath.Base(file.Filename))

		// Save the file to the destination
		if err := c.SaveUploadedFile(file, dst); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Unable to save the file"})
			return
		}
		libraryPath := os.Getenv("PKCS11_LIB")
		if libraryPath == "" {
			log.Fatal("PKCS11_LIB environment variable is not set")
		}

		// HSM configuration
		slot := uint(slotID)

			// Initialize PKCS#11 and log in to the HSM
		p, session, err := certificate.InitializePKCS11(libraryPath, slotPIN, slot)
		if err != nil {
			log.Fatalf("Initialization failed: %v", err)
		}
		defer func() {
			p.Logout(session)
			p.CloseSession(session)
			p.Finalize()
		}()
		// Load certificate data from file
		certData, err := certificate.LoadCertificateFromFile(dst)
		if err != nil {
			log.Fatalf("Failed to load certificate: %v", err)
		}

		// Import certificate into HSM
		err = certificate.ImportCertificateToHSM(p, session, certData, CertificateName)
		if err != nil {
			log.Fatalf("Failed to import certificate to HSM: %v", err)
		}
		// Return a success response
		c.JSON(http.StatusOK, gin.H{
			"message": "File uploaded successfully",
			"slotPIN": slotPIN,
			"CertificateName": CertificateName,
			"slotID": slotID,
			"file":    file.Filename,
			"path":    "/uploads/" + file.Filename,
		})
	})

	router.POST("/create/desCreate", func(c *gin.Context) {
		var req DESCreate

		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
			return
		}

		libraryPath := os.Getenv("PKCS11_LIB")
		if libraryPath == "" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "PKCS11_LIB environment variable is not set"})
			return
		}

		manager, err := create.NewHSMManager(libraryPath, req.Slot)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to initialize HSM manager"})
			return
		}
		defer manager.Finalize()

		if err := manager.Login(req.Pin); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Failed to log in to HSM"})
			return
		}
		defer manager.Logout()

		keyHandle, err := manager.GenerateDES3Key(req.KeyLabel, req.KeyID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate DES3 key"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message":    "DES3 key generated successfully",
			"keyLabel":   req.KeyLabel,
			"keyHandle":  keyHandle,
			"keyID":      req.KeyID,
		})
	})



	router.POST("/import/EC-keys", func(c *gin.Context) {
		// Parse form data
		slotIDStr := c.PostForm("slotID")
		slotPIN := c.PostForm("slotPIN")
		keyLabel := c.PostForm("keyLabel")

		// Parse SlotID
		slotID, err := strconv.Atoi(slotIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid SlotID"})
			return
		}

		// Handle uploaded private key file
		privateFile, err := c.FormFile("privateKey")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Private key file is required"})
			return
		}

		// Save uploaded private key file temporarily
		privateKeyPath := "./tmp_" + privateFile.Filename
		if err := c.SaveUploadedFile(privateFile, privateKeyPath); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save private key file"})
			return
		}
		defer os.Remove(privateKeyPath)

		// Handle uploaded public key file
		publicFile, err := c.FormFile("publicKey")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Public key file is required"})
			return
		}

		// Save uploaded public key file temporarily
		publicKeyPath := "./tmp_" + publicFile.Filename
		if err := c.SaveUploadedFile(publicFile, publicKeyPath); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save public key file"})
			return
		}
		defer os.Remove(publicKeyPath)

		// Load keys from the uploaded files
		privateKey, err := loadECPrivateKeyFromFile(privateKeyPath)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load private key"})
			return
		}

		publicKey, err := loadECPublicKeyFromFile(publicKeyPath)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load public key"})
			return
		}

		// Initialize PKCS#11 module
		libraryPath := os.Getenv("PKCS11_LIB")
		if libraryPath == "" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "PKCS11_LIB environment variable is not set"})
			return
		}

		p := pkcs11.New(libraryPath)
		if err := p.Initialize(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to initialize PKCS#11 library"})
			return
		}
		defer p.Finalize()

		// Open session
		session, err := p.OpenSession(uint(slotID), pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to open session"})
			return
		}
		defer p.CloseSession(session)

		// Log in
		if err := p.Login(session, pkcs11.CKU_USER, slotPIN); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Failed to log in"})
			return
		}
		defer p.Logout(session)

		// Define EC curve parameters
		oidNamedCurveP256 := []byte{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}

		// Import private key
		privateKeyTemplate := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel),
			pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, oidNamedCurveP256),
			pkcs11.NewAttribute(pkcs11.CKA_VALUE, privateKey.D.Bytes()),
		}
		privHandle, err := p.CreateObject(session, privateKeyTemplate)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to import private key"})
			return
		}

		// Import public key
		publicKeyTemplate := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, oidNamedCurveP256),
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, marshalECPublicKey(publicKey)),
		}
		pubHandle, err := p.CreateObject(session, publicKeyTemplate)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to import public key"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message":         "Keys imported successfully",
			"privateKeyHandle": privHandle,
			"publicKeyHandle":  pubHandle,
		})
	})

		// Endpoint to encrypt data
	router.POST("/encrypt/rsaEncrypt", func(c *gin.Context) {
		var req struct {
			Slot     uint   `json:"slot"`
			Pin      string `json:"pin"`
			Label    string `json:"label"`
			Plaintext string `json:"plaintext"`
		}

		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
			return
		}

		libraryPath := os.Getenv("PKCS11_LIB")
		if libraryPath == "" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "PKCS11_LIB environment variable is not set"})
			return
		}

		// Initialize PKCS#11
		p, session, err := encrypt.InitializePKCS11(libraryPath, req.Pin, req.Slot)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to initialize PKCS#11"})
			return
		}
		defer p.Finalize()
		defer p.CloseSession(session)
		defer p.Logout(session)

		// Find RSA key
		privKeyHandle, pubKey, err := encrypt.FindRSAKey(p, session, req.Label)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to find RSA key"})
			return
		}
		fmt.Println(privKeyHandle)

		// Encrypt data
		ciphertext, err := encrypt.EncryptDataRSA(pubKey, []byte(req.Plaintext))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encrypt data"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"ciphertext": ciphertext,
		})
	})

	router.POST("/decrypt/rsaDecrypt", func(c *gin.Context) {
		var req struct {
			Slot       uint   `json:"slot"`
			Pin        string `json:"pin"`
			Label      string `json:"label"`
			Ciphertext string `json:"ciphertext"` // Base64 formatında string alıyoruz
		}
	
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
			return
		}
	
		libraryPath := os.Getenv("PKCS11_LIB")
		if libraryPath == "" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "PKCS11_LIB environment variable is not set"})
			return
		}
	
		// Initialize PKCS#11
		p, session, err := encrypt.InitializePKCS11(libraryPath, req.Pin, req.Slot)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to initialize PKCS#11"})
			return
		}
		defer p.Finalize()
		defer p.CloseSession(session)
		defer p.Logout(session)
	
		// Find RSA key
		privKeyHandle, _, err := encrypt.FindRSAKey(p, session, req.Label)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to find RSA key"})
			return
		}
	
		// Decode the Base64 ciphertext to []byte
		ciphertextBytes, err := base64.StdEncoding.DecodeString(req.Ciphertext)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Base64 encoded ciphertext"})
			return
		}
	
		// Decrypt data
		plaintext, err := encrypt.DecryptDataRSA(p, session, privKeyHandle, ciphertextBytes)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decrypt data"})
			return
		}
	
		c.JSON(http.StatusOK, gin.H{
			"plaintext": string(plaintext),
		})
	})

    router.Run(":8080")
}
// EC import işlemi için Start

// Function to load a PEM file and decode the EC private key
func loadECPrivateKeyFromFile(filepath string) (*ecdsa.PrivateKey, error) {
	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

// Function to load a PEM file and decode the EC public key
func loadECPublicKeyFromFile(filepath string) (*ecdsa.PublicKey, error) {
	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	publicKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an EC public key")
	}
	return publicKey, nil
}

// Helper function to marshal the EC public key point to ASN.1 format for PKCS#11
func marshalECPublicKey(pub *ecdsa.PublicKey) []byte {
	x, y := pub.X.Bytes(), pub.Y.Bytes()

	// ASN.1 OCTET STRING format
	ecPoint := make([]byte, 1+len(x)+len(y))
	ecPoint[0] = 0x04 // Uncompressed point indicator
	copy(ecPoint[1:1+len(x)], x)
	copy(ecPoint[1+len(x):], y)

	return ecPoint
}

// EC import işlemi için Stop

// createUploadsDirectory ensures the upload directory exists
func createUploadsDirectory(path string) error {
	return os.MkdirAll(path, os.ModePerm)
}