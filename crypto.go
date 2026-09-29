package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
)

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

func loadEncryptionKey() error {
	const keyPath = "appdata/encryption.key"

	if err := os.MkdirAll("appdata", 0700); err != nil {
		return err
	}

	// Existing key
	key, err := os.ReadFile(keyPath)
	if err == nil {
		if len(key) != 32 {
			return fmt.Errorf("invalid encryption key size: %d", len(key))
		}

		encryptionKey = key
		return nil
	}

	// Generate new 32-byte key
	key = make([]byte, 32)

	if _, err := rand.Read(key); err != nil {
		return err
	}

	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		return err
	}

	encryptionKey = key
	return nil
}
