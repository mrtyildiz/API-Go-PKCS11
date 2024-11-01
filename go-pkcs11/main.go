// /go-pkcs11/main.go
package main

import (
    "github.com/gin-gonic/gin"
    "fmt"
	"net/http"
    "go-pkcs11/create"
)

type AES_Create struct {
	SlotID   int    `json:"slot_id"`  // binding: "required" kaldırıldı
	SlotPIN  string `json:"slot_pin" binding:"required"`
	KeySize  int    `json:"key_size" binding:"required"`
	KeyLabel string `json:"key_label" binding:"required"`
}

type KeyRSARequest struct {
	SlotID   *int   `json:"slot_id" binding:"required"`
	UserPin  string `json:"user_pin" binding:"required"`
	KeySize  int    `json:"key_size" binding:"required"`
	KeyLabel string `json:"key_label" binding:"required"`
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
		result, err := create.GenerateRSAKey(*req.SlotID, req.UserPin, req.KeySize, req.KeyLabel)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": result})
	})

    router.Run(":8080")
}
