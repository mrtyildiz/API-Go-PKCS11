// /go-pkcs11/main.go
package main

import (
    "github.com/gin-gonic/gin"
	"encoding/hex"
    "fmt"
	"net/http"
	"strings"
    "go-pkcs11/create"
	"go-pkcs11/encrypt"
	"os"
	"log"
	"path/filepath"
	"go-pkcs11/remove"
	"go-pkcs11/certificate"
	"strconv"
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


    router.Run(":8080")
}
// createUploadsDirectory ensures the upload directory exists
func createUploadsDirectory(path string) error {
	return os.MkdirAll(path, os.ModePerm)
}