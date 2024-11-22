package main

/*
#cgo LDFLAGS: -L/lib64 -lprocryptoki
#include <stdint.h>
#include <stdlib.h>
#include "procryptoki.h"

typedef struct {
    unsigned long Type;
    void *ValuePtr;
    unsigned long ValueLen;
} Configuration;

extern unsigned long C_PDS_SetConfigurationValue(const char *ha_pin, unsigned long ha_pin_len,
                                          Configuration *config, unsigned long config_count);
*/
import "C"
import (
	"fmt"
	"log"
	"os"
	"strings"
	"unsafe"

	"github.com/miekg/pkcs11"
)

const (
	CK_PDS_CONFIG_HW_CRYPTO_DISABLED        = 0x80000001
	CK_PDS_CONFIG_EXPERIMENTAL_FEATURES_ENABLED = 0x80000002
)

func TokenCreate(hoPin, haPin, tokenLabel, soPin, userPin string) string {
	pkcs11LibPath := os.Getenv("HSM_SO_File")
	if pkcs11LibPath == "" {
		pkcs11LibPath = "/lib64/libprocryptoki.so" // Varsayılan yol
	}

	p := pkcs11.New(pkcs11LibPath)
	if p == nil {
		log.Fatal("Failed to initialize PKCS#11 module")
	}
	defer p.Destroy()

	if err := p.Initialize(); err != nil {
		log.Fatalf("Failed to initialize PKCS#11: %v", err)
	}
	defer p.Finalize()

	slots, err := p.GetSlotList(true)
	if err != nil {
		log.Fatalf("Failed to get slot list: %v", err)
	}

	if len(slots) == 0 {
		log.Fatal("No slots found. Is the HSM device connected?")
	}

	fmt.Printf("Available slots: %v\n", slots)
	slot := slots[len(slots)-1]

	tokenInfo, err := p.GetTokenInfo(slot)
	if err != nil {
		log.Fatalf("Failed to get token info: %v", err)
	}
	fmt.Printf("Using token: %s\n", strings.TrimSpace(tokenInfo.Label))

	session, err := p.OpenSession(slot, pkcs11.CKF_RW_SESSION|pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		log.Fatalf("Failed to open session: %v", err)
	}
	defer p.CloseSession(session)

	if err := p.Login(session, pkcs11.CKU_SO, hoPin); err != nil {
		log.Fatalf("HSM Login failed: %v", err)
	}

	configValue := C.char(1)
	config := C.Configuration{
		Type:     C.CK_PDS_CONFIG_HW_CRYPTO_DISABLED,
		ValuePtr: unsafe.Pointer(&configValue),
		ValueLen: C.ulong(1),
	}

	haPinC := C.CString(haPin)
	defer C.free(unsafe.Pointer(haPinC))

	rv := C.C_PDS_SetConfigurationValue(haPinC, C.ulong(len(haPin)), &config, C.ulong(1))
	if rv != 0 {
		log.Fatalf("C_PDS_SetConfigurationValue failed with error code: 0x%X", rv)
	}

	err = p.InitToken(slot, soPin, tokenLabel)
	if err != nil {
		log.Fatalf("Failed to initialize token: %v", err)
	}

	err = p.InitPIN(session, userPin)
	if err != nil {
		log.Fatalf("Failed to initialize user PIN: %v", err)
	}

	if err := p.Logout(session); err != nil {
		log.Fatalf("Failed to logout: %v", err)
	}

	return "Token is created"
}

func main() {
	hoPin := "1111"
	haPin := "1111"
	soPin := "1111"
	userPin := "1111"

	for i := 1; i < 20; i++ {
		tokenLabel := fmt.Sprintf("Token_Name%d", i)
		result := TokenCreate(hoPin, haPin, tokenLabel, soPin, userPin)
		fmt.Printf("Token Label: %s, Result: %s\n", tokenLabel, result)
	}
}
