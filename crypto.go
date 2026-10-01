package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// Environment variable holding a hex-encoded 32-byte key. Set it to keep the
// key off the same disk as the vault.
const encryptionKeyEnv = "API_VAULT_ENCRYPTION_KEY"

func encrypt(key []byte, plaintext string) ([]byte, error) {

	block, err := aes.NewCipher(key)

	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)

	if err != nil {
		return nil, err
	}

	nonce := make(
		[]byte,
		gcm.NonceSize(),
	)

	if _, err := io.ReadFull(
		rand.Reader,
		nonce,
	); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(
		nonce,
		nonce,
		[]byte(plaintext),
		nil,
	)

	return ciphertext, nil
}

func decrypt(key []byte, ciphertext []byte) (string, error) {

	block, err := aes.NewCipher(key)

	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)

	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()

	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf(
			"ciphertext too short",
		)
	}

	nonce := ciphertext[:nonceSize]
	data := ciphertext[nonceSize:]

	plaintext, err := gcm.Open(
		nil,
		nonce,
		data,
		nil,
	)

	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// loadEncryptionKey resolves the AES key, preferring a key supplied from
// outside the vault directory.
//
// Order:
//  1. $API_VAULT_ENCRYPTION_KEY (hex-encoded 32 bytes)
//  2. storage.key_file from the config
//  3. <appfolder>/encryption.key, generated on first run
//
// Option 3 stores the key in the same directory as the encrypted secrets, so
// anyone who can read the data files can also decrypt them. It stays the
// default so existing installs keep working, but it warns on every start.
func loadEncryptionKey() error {
	if raw := strings.TrimSpace(os.Getenv(encryptionKeyEnv)); raw != "" {
		key, err := hex.DecodeString(raw)
		if err != nil {
			return fmt.Errorf("%s is not valid hex: %w", encryptionKeyEnv, err)
		}

		if len(key) != 32 {
			return fmt.Errorf("%s must decode to 32 bytes, got %d", encryptionKeyEnv, len(key))
		}

		encryptionKey = key
		logEvent("CRYPTO", "Encryption key loaded from "+encryptionKeyEnv)
		return nil
	}

	keyPath := config.Storage.KeyFile
	external := keyPath != ""

	if !external {
		keyPath = filepath.Join(appfolder, "encryption.key")
	}

	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		return err
	}

	key, err := os.ReadFile(keyPath)
	if err == nil {
		if len(key) != 32 {
			return fmt.Errorf("invalid encryption key size in %s: %d bytes, expected 32", keyPath, len(key))
		}

		warnKeyPermissions(keyPath)

		if !external {
			warnKeyBesideData(keyPath)
		}

		encryptionKey = key
		return nil
	}

	if !os.IsNotExist(err) {
		return fmt.Errorf("failed to read %s: %w", keyPath, err)
	}

	// Generate new 32-byte key
	key = make([]byte, 32)

	if _, err := rand.Read(key); err != nil {
		return err
	}

	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		return err
	}

	logEvent("CRYPTO", "Generated a new encryption key at "+keyPath)

	if !external {
		warnKeyBesideData(keyPath)
	}

	encryptionKey = key
	return nil
}

func warnKeyBesideData(keyPath string) {
	log.Printf(
		"[WARN] The encryption key lives next to the encrypted secrets (%s). "+
			"Anyone who can read that directory can decrypt the vault. Set %s or storage.key_file to move it.",
		keyPath, encryptionKeyEnv,
	)
}

func warnKeyPermissions(keyPath string) {
	info, err := os.Stat(keyPath)
	if err != nil {
		return
	}

	if mode := info.Mode().Perm(); mode&0077 != 0 {
		log.Printf("[WARN] %s is readable beyond its owner (mode %04o); tighten it to 0600.", keyPath, mode)
	}
}
