package main

import (
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
)

// Handles saving new API keys

func handleSaveSecretKey(w http.ResponseWriter, r *http.Request) {

	userID, ok := getSessionUserID(r)

	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
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
	data.CreatedBy = userID

	// Override existing secret
	for i := range secrets {

		if secrets[i].Key == data.Key {

			secrets[i].Value = data.Value

			// Keep original creator
			if secrets[i].CreatedBy != "" {
				data.CreatedBy = secrets[i].CreatedBy
			}

			secrets[i] = data

			if err := saveSecrets(secrets); err != nil {
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

	if err := saveSecrets(secrets); err != nil {
		http.Error(w, "Failed to save secret", 500)
		return
	}

	jsonOut(w, map[string]string{
		"status": "saved",
	})
}

// Handles viewing API Keys between usernames so that one cannot see the other's api key
// The admin can see all the api keys and modify them.

func handleViewSecrets(w http.ResponseWriter, r *http.Request) {

	userID, ok := getSessionUserID(r)

	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Load users
	users, err := loadJSON[APIUser](usersFile)

	if err != nil {
		log.Printf("[ERROR] Failed to load users: %v", err)
		http.Error(w, "Failed to load users", 500)
		return
	}

	// Find current user
	var currentUser *APIUser

	for i := range users {
		if users[i].ID == userID {
			currentUser = &users[i]
			break
		}
	}

	if currentUser == nil {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	// ================= ADMIN =================
	// Admin can see EVERYTHING.
	if currentUser.Role == "admin" {

		var result []Secret

		for _, secret := range secrets {

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

			if id == userID {
				allowed[permission.Key] = true
				break
			}
		}
	}

	var result []Secret

	for _, secret := range secrets {

		// User can see:
		// 1. Their own secrets
		// 2. Secrets explicitly shared with them

		canView := secret.CreatedBy == userID || allowed[secret.Key]

		if !canView {
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

// Handles deleting the api keys

func handleDeleteSecret(w http.ResponseWriter, r *http.Request) {

	if !isAuthenticated(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var data struct {
		Key string `json:"key"`
	}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	for i, secret := range secrets {

		if secret.Key != data.Key {
			continue
		}

		secrets = append(
			secrets[:i],
			secrets[i+1:]...,
		)

		if err := saveSecrets(secrets); err != nil {
			http.Error(w, "Failed to save secrets", 500)
			return
		}

		jsonOut(w, map[string]string{
			"status": "deleted",
		})

		return
	}

	http.Error(w, "Secret not found", http.StatusNotFound)
}

// Switching between Saving, deleting, viewing keys

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
