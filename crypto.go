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

const encryptionKeyEnv = "API_VAULT_ENCRYPTION_KEY"

// encrypt encrypts plaintext using AES-256-GCM.
//
// The returned ciphertext contains the nonce followed by the encrypted data.
func encrypt(key []byte, plaintext string) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf(
			"invalid encryption key size: got %d bytes, expected 32",
			len(key),
		)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())

	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(
		nonce,
		nonce,
		[]byte(plaintext),
		nil,
	)

	return ciphertext, nil
}

// decrypt decrypts AES-256-GCM ciphertext.
//
// The ciphertext must contain the nonce followed by the encrypted data.
func decrypt(key []byte, ciphertext []byte) (string, error) {
	if len(key) != 32 {
		return "", fmt.Errorf(
			"invalid encryption key size: got %d bytes, expected 32",
			len(key),
		)
	}

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
		return "", fmt.Errorf("ciphertext too short")
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
		return "", fmt.Errorf("failed to decrypt ciphertext: %w", err)
	}

	return string(plaintext), nil
}

// loadEncryptionKey loads the AES-256 encryption key.
//
// Priority:
//  1. API_VAULT_ENCRYPTION_KEY environment variable
//  2. storage.key_file from config.yml
//  3. <appfolder>/encryption.key
//
// The key is 32 bytes and is used for AES-256-GCM.
func loadEncryptionKey() error {

	// ------------------------------------------------------------
	// 1. Environment variable
	// ------------------------------------------------------------

	if raw := strings.TrimSpace(os.Getenv(encryptionKeyEnv)); raw != "" {
		key, err := hex.DecodeString(raw)
		if err != nil {
			return fmt.Errorf(
				"%s is not valid hexadecimal: %w",
				encryptionKeyEnv,
				err,
			)
		}

		if len(key) != 32 {
			return fmt.Errorf(
				"%s must decode to exactly 32 bytes, got %d",
				encryptionKeyEnv,
				len(key),
			)
		}

		encryptionKey = key

		logEvent(
			"CRYPTO",
			"Encryption key loaded from "+encryptionKeyEnv,
		)

		return nil
	}

	// ------------------------------------------------------------
	// 2. Configured key file
	// ------------------------------------------------------------

	keyPath := strings.TrimSpace(config.Storage.KeyFile)
	external := keyPath != ""

	// ------------------------------------------------------------
	// 3. Default key file
	// ------------------------------------------------------------

	if !external {
		appFolder := strings.TrimSpace(config.Storage.AppFolder)

		if appFolder == "" {
			appFolder = "appdata"
		}

		keyPath = filepath.Join(
			appFolder,
			"encryption.key",
		)
	}

	// Make sure the parent directory exists.
	parentDir := filepath.Dir(keyPath)

	if err := os.MkdirAll(parentDir, 0700); err != nil {
		return fmt.Errorf(
			"failed to create encryption key directory: %w",
			err,
		)
	}

	// ------------------------------------------------------------
	// Load existing key
	// ------------------------------------------------------------

	key, err := os.ReadFile(keyPath)

	if err == nil {

		if len(key) != 32 {
			return fmt.Errorf(
				"invalid encryption key in %s: got %d bytes, expected 32",
				keyPath,
				len(key),
			)
		}

		warnKeyPermissions(keyPath)

		if !external {
			warnKeyBesideData(keyPath)
		}

		encryptionKey = key

		logEvent(
			"CRYPTO",
			"Encryption key loaded from "+keyPath,
		)

		return nil
	}

	// An error other than "file does not exist" is a real failure.
	if !os.IsNotExist(err) {
		return fmt.Errorf(
			"failed to read encryption key %s: %w",
			keyPath,
			err,
		)
	}

	// ------------------------------------------------------------
	// Generate new AES-256 key
	// ------------------------------------------------------------

	key = make([]byte, 32)

	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf(
			"failed to generate encryption key: %w",
			err,
		)
	}

	// Write with restrictive permissions.
	if err := os.WriteFile(
		keyPath,
		key,
		0600,
	); err != nil {
		return fmt.Errorf(
			"failed to save encryption key %s: %w",
			keyPath,
			err,
		)
	}

	encryptionKey = key

	logEvent(
		"CRYPTO",
		"Generated a new encryption key at "+keyPath,
	)

	if !external {
		warnKeyBesideData(keyPath)
	}

	return nil
}

// warnKeyBesideData warns when the encryption key is stored inside the
// application's data directory.
func warnKeyBesideData(keyPath string) {
	log.Printf(
		"[WARN] Encryption key is stored at %s. "+
			"Anyone who can read this directory can decrypt the vault. "+
			"Set %s or storage.key_file to move the key elsewhere.",
		keyPath,
		encryptionKeyEnv,
	)
}

// warnKeyPermissions checks whether the key file is accessible by
// users other than its owner.
func warnKeyPermissions(keyPath string) {
	info, err := os.Stat(keyPath)
	if err != nil {
		return
	}

	mode := info.Mode().Perm()

	if mode&0077 != 0 {
		log.Printf(
			"[WARN] %s is readable beyond its owner (mode %04o). "+
				"Tighten permissions to 0600.",
			keyPath,
			mode,
		)
	}
}
