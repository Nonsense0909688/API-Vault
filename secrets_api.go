package main

import (
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
)

// Handles saving new API keys.

func handleSaveSecretKey(w http.ResponseWriter, r *http.Request) {

	user, ok := requireUser(w, r)
	if !ok {
		return
	}

	var data Secret

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if data.Key == "" {
		http.Error(w, "Secret key is required", http.StatusBadRequest)
		return
	}

	if data.Value == "" {
		http.Error(w, "Secret value is required", http.StatusBadRequest)
		return
	}

	// Saving under a key someone else owns silently replaced their secret.
	if !canAdministerSecret(user, data.Key) {
		logEvent("ACCESS_DENIED", "User "+user.Username+" tried to overwrite "+data.Key)
		http.Error(w, "A secret with that name belongs to another user", http.StatusForbidden)
		return
	}

	encryptedValue, err := encrypt(
		encryptionKey,
		data.Value,
	)

	if err != nil {
		log.Printf(
			"[ERROR] Failed to encrypt secret '%s': %v",
			data.Key,
			err,
		)

		http.Error(w, "Failed to encrypt secret", 500)
		return
	}

	data.Value = hex.EncodeToString(encryptedValue)
	data.CreatedBy = user.ID

	secretsMu.Lock()
	defer secretsMu.Unlock()

	// Override existing secret
	for i := range secrets {

		if secrets[i].Key == data.Key {

			// Keep original creator
			if secrets[i].CreatedBy != "" {
				data.CreatedBy = secrets[i].CreatedBy
			}

			previous := secrets[i]
			secrets[i] = data

			if err := saveSecretsLocked(); err != nil {
				secrets[i] = previous
				http.Error(w, "Failed to save secret", 500)
				return
			}

			jsonOut(w, map[string]string{
				"status": "overridden",
			})

			return
		}
	}

	// Create new secret
	secrets = append(secrets, data)

	if err := saveSecretsLocked(); err != nil {
		secrets = secrets[:len(secrets)-1]
		http.Error(w, "Failed to save secret", 500)
		return
	}

	jsonOut(w, map[string]string{
		"status": "saved",
	})
}

// Handles viewing API keys so that one user cannot see another's.
// The admin can see all the api keys and modify them.

func handleViewSecrets(w http.ResponseWriter, r *http.Request) {

	currentUser, ok := requireUser(w, r)
	if !ok {
		return
	}

	// Permissions file is optional.
	// If it doesn't exist, loadJSON returns an empty list.
	permissions, err := loadJSON[Permission](permissionsFile)

	if err != nil {
		log.Printf("[ERROR] Failed to load permissions: %v", err)
		http.Error(w, "Failed to load permissions", 500)
		return
	}

	// Build list of secrets explicitly shared with this user.
	allowed := make(map[string]bool)

	for _, permission := range permissions {

		for _, id := range permission.UserIDs {

			if id == currentUser.ID {
				allowed[permission.Key] = true
				break
			}
		}
	}

	admin := isAdmin(currentUser)

	secretsMu.RLock()
	defer secretsMu.RUnlock()

	result := make([]Secret, 0, len(secrets))

	for _, secret := range secrets {

		// A user can see:
		// 1. Their own secrets
		// 2. Secrets explicitly shared with them
		// An admin sees everything.
		if !admin && secret.CreatedBy != currentUser.ID && !allowed[secret.Key] {
			continue
		}

		encryptedValue, err := hex.DecodeString(secret.Value)

		if err != nil {
			log.Printf(
				"[ERROR] Failed to decode secret '%s': %v",
				secret.Key,
				err,
			)

			http.Error(w, "Failed to decode secret", 500)
			return
		}

		decryptedValue, err := decrypt(
			encryptionKey,
			encryptedValue,
		)

		if err != nil {
			log.Printf(
				"[ERROR] Failed to decrypt secret '%s': %v",
				secret.Key,
				err,
			)

			http.Error(w, "Failed to decrypt secret", 500)
			return
		}

		result = append(result, Secret{
			Key:       secret.Key,
			Value:     decryptedValue,
			CreatedBy: secret.CreatedBy,
		})
	}

	jsonOut(w, result)
}

// Handles deleting the api keys.

func handleDeleteSecret(w http.ResponseWriter, r *http.Request) {

	user, ok := requireUser(w, r)
	if !ok {
		return
	}

	var data struct {
		Key string `json:"key"`
	}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if data.Key == "" {
		http.Error(w, "Secret key is required", http.StatusBadRequest)
		return
	}

	if _, exists := secretOwner(data.Key); !exists {
		http.Error(w, "Secret not found", http.StatusNotFound)
		return
	}

	// Deletion only checked that the caller was logged in, so any account
	// could wipe any other account's secrets.
	if !canAdministerSecret(user, data.Key) {
		logEvent("ACCESS_DENIED", "User "+user.Username+" tried to delete "+data.Key)
		http.Error(w, "Not allowed to delete this secret", http.StatusForbidden)
		return
	}

	secretsMu.Lock()

	removed := false
	remaining := make([]Secret, 0, len(secrets))

	for _, secret := range secrets {
		if secret.Key == data.Key {
			removed = true
			continue
		}

		remaining = append(remaining, secret)
	}

	if !removed {
		secretsMu.Unlock()
		http.Error(w, "Secret not found", http.StatusNotFound)
		return
	}

	previous := secrets
	secrets = remaining

	if err := saveSecretsLocked(); err != nil {
		secrets = previous
		secretsMu.Unlock()
		http.Error(w, "Failed to save secrets", 500)
		return
	}

	secretsMu.Unlock()

	// Drop the sharing entry too, so a later secret reusing the name does not
	// inherit the old grants.
	if err := removePermission(data.Key); err != nil {
		log.Printf("[ERROR] Failed to clear permissions for '%s': %v", data.Key, err)
	}

	jsonOut(w, map[string]string{
		"status": "deleted",
	})
}

func removePermission(key string) error {
	permissionsMu.Lock()
	defer permissionsMu.Unlock()

	permissions, err := loadJSON[Permission](permissionsFile)
	if err != nil {
		return err
	}

	remaining := make([]Permission, 0, len(permissions))
	changed := false

	for _, permission := range permissions {
		if permission.Key == key {
			changed = true
			continue
		}

		remaining = append(remaining, permission)
	}

	if !changed {
		return nil
	}

	return saveJSON(permissionsFile, remaining)
}

// Switching between saving, deleting and viewing keys.

func handleAPISecrets(w http.ResponseWriter, r *http.Request) {

	switch r.Method {

	case http.MethodGet:
		handleViewSecrets(w, r)

	case http.MethodPost:
		handleSaveSecretKey(w, r)

	case http.MethodDelete:
		handleDeleteSecret(w, r)

	default:
		http.Error(
			w,
			"Method not allowed",
			http.StatusMethodNotAllowed,
		)
	}
}
