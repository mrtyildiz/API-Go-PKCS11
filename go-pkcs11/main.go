// /go-pkcs11/main.go
package main

import (
    "github.com/gin-gonic/gin"
	"encoding/hex"
    "fmt"
	"net/http"
    "go-pkcs11/create"
	"go-pkcs11/encrypt"
	"os"
	"log"
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
	Slot       uint   `json:"slot" binding:"required"`       // HSM Slot ID
	Pin        string `json:"pin" binding:"required"`        // HSM PIN
	KeyLabel   string `json:"key_label" binding:"required"`  // Anahtar Etiketi
	CipherText string `json:"cipher_text" binding:"required"` // Şifrelenmiş Metin (Hexadecimal)
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
	router.POST("/encrypt", func(c *gin.Context) {
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

    router.Run(":8080")
}
