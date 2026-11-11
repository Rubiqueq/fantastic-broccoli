package main

import (
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
	"path/filepath"
	"strings"

	"rubikasaf/rubingo"
)

// restoreSession validates a previously authorized Rubika account against the
// provider. It never requests OTP and never starts a persisted sending queue.
// A failed validation leaves the service unauthenticated, requiring manual login.
func restoreSession() {
	base := filepath.Join(queueDataDir(), "rubika_saf")
	sessionPath := base + ".session"
	if _, err := os.Stat(sessionPath); err != nil {
		return
	}
	client, err := rubingo.NewClient(base)
	if err != nil {
		log.Printf("session_restore_init_failed")
		return
	}
	_ = os.Chmod(sessionPath, 0600)
	if err = client.Connect(); err != nil {
		log.Printf("session_restore_connect_failed")
		return
	}
	if client.Auth == "" || client.GUID == "" || client.PrivateKey == "" {
		_ = client.Disconnect()
		return
	}
	crypto := rubingo.NewCrypto()
	client.Key = crypto.Passphrase(client.Auth)
	client.DecodeAuthStr = crypto.DecodeAuth(client.Auth)

	keyPEM := strings.TrimSpace(client.PrivateKey)
	if !strings.HasPrefix(keyPEM, "-----BEGIN RSA PRIVATE KEY-----") {
		keyPEM = "-----BEGIN RSA PRIVATE KEY-----\n" + keyPEM
	}
	if !strings.HasSuffix(keyPEM, "-----END RSA PRIVATE KEY-----") {
		keyPEM += "\n-----END RSA PRIVATE KEY-----"
	}
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		log.Printf("session_restore_invalid_private_key")
		_ = client.Disconnect()
		return
	}
	rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Printf("session_restore_invalid_private_key")
		_ = client.Disconnect()
		return
	}
	client.ImportKey = rsaKey
	if _, err := client.GetMe(); err != nil {
		log.Printf("session_restore_provider_validation_failed")
		_ = client.Disconnect()
		return
	}
	app.Lock()
	app.client = client
	app.authenticated = true
	app.Unlock()
	log.Printf("session_restore_authenticated")
}
