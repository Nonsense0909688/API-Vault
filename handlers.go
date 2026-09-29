package main

import (
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"time"
)

// Panel Handler

func handleRoot(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		logEvent("AUTH_FAILED", "Unauthorized access to dashboard")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	logEvent("DASHBOARD", "Dashboard accessed")

	if err := templates.ExecuteTemplate(w, "index.html", nil); err != nil {
		log.Printf("[ERROR] Failed to execute index template: %v", err)
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

// Login Handler

func handleLogin(w http.ResponseWriter, r *http.Request) {
	logEvent("LOGIN_PAGE", "Login page requested")

	if err := templates.ExecuteTemplate(w, "login.html", nil); err != nil {
		log.Printf("[ERROR] Failed to execute login template: %v", err)
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

// Post Login Sequence

func handleLoginPost(w http.ResponseWriter, r *http.Request) {

	logEvent(
		"LOGIN_ATTEMPT",
		"Login request received",
	)

	var data ViewingKey

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {

		log.Printf(
			"[ERROR] Invalid login JSON: %v",
			err,
		)

		http.Error(
			w,
			"Invalid JSON",
			http.StatusBadRequest,
		)

		return
	}

	// Temporary password
	if data.Key != config.Auth.Password {
		logEvent("AUTH_FAILED", "Invalid login credentials")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	sessionID, err := createSession()

	if err != nil {

		log.Printf(
			"[ERROR] Failed to generate session ID: %v",
			err,
		)

		http.Error(
			w,
			"Failed to create session",
			http.StatusInternalServerError,
		)

		return
	}

	sessions[sessionID] = time.Now().Add(sessionDuration)

	if err := saveSessions(sessions); err != nil {

		log.Printf(
			"[ERROR] Failed to save sessions: %v",
			err,
		)

		delete(sessions, sessionID)

		http.Error(
			w,
			"Failed to save session",
			http.StatusInternalServerError,
		)

		return
	}

	setSessionCookie(w, sessionID)

	logEvent(
		"LOGIN_SUCCESS",
		"New session created",
	)

	http.Redirect(
		w,
		r,
		"/",
		http.StatusSeeOther,
	)
}

// Logout Handler

func handleLogout(w http.ResponseWriter, r *http.Request) {

	cookie, err := r.Cookie("session")

	if err == nil {

		delete(sessions, cookie.Value)

		logEvent(
			"LOGOUT",
			"Session invalidated",
		)

	} else {

		logEvent(
			"LOGOUT",
			"Logout requested without session",
		)
	}

	if err := saveSessions(sessions); err != nil {

		log.Printf(
			"[ERROR] Failed to save sessions: %v",
			err,
		)

		http.Error(
			w,
			"Failed to save session",
			http.StatusInternalServerError,
		)

		return
	}

	clearSessionCookie(w)

	http.Redirect(
		w,
		r,
		"/login",
		http.StatusSeeOther,
	)
}

// API Keys handler
// taking in data {key, value} & encrypting with AES-256.

func handleSaveSecretKey(w http.ResponseWriter, r *http.Request) {

	if !isAuthenticated(r) {

		logEvent(
			"AUTH_FAILED",
			"Unauthorized save attempt",
		)

		http.Error(
			w,
			"Unauthorized",
			http.StatusUnauthorized,
		)

		return
	}

	var data Secret

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {

		log.Printf(
			"[ERROR] Invalid secret JSON: %v",
			err,
		)

		http.Error(
			w,
			"Invalid JSON",
			http.StatusBadRequest,
		)

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

		http.Error(
			w,
			"Failed to encrypt secret",
			http.StatusInternalServerError,
		)

		return
	}

	data.Value = hex.EncodeToString(encryptedValue)

	for i, secret := range secrets {

		if secret.Key == data.Key {

			secrets[i].Value = data.Value

			if err := saveSecrets(secrets); err != nil {

				log.Printf(
					"[ERROR] Failed to override secret '%s': %v",
					data.Key,
					err,
				)

				http.Error(
					w,
					"Failed to save secret",
					http.StatusInternalServerError,
				)

				return
			}

			log.Printf(
				"[SECRET] Secret '%s' overridden",
				data.Key,
			)

			w.Header().Set(
				"Content-Type",
				"application/json",
			)

			json.NewEncoder(w).Encode(
				map[string]string{
					"status": "overridden",
				},
			)

			return
		}
	}

	secrets = append(secrets, data)

	if err := saveSecrets(secrets); err != nil {

		log.Printf(
			"[ERROR] Failed to save secret '%s': %v",
			data.Key,
			err,
		)

		http.Error(
			w,
			"Failed to save secret",
			http.StatusInternalServerError,
		)

		return
	}

	log.Printf(
		"[SECRET] Secret '%s' created",
		data.Key,
	)

	w.Header().Set(
		"Content-Type",
		"application/json",
	)

	json.NewEncoder(w).Encode(
		map[string]string{
			"status": "saved",
		},
	)
}

// API Keys Viewing Handler
// checking for authentication nd then sending over secrets list

func handleViewSecrets(w http.ResponseWriter, r *http.Request) {

	if !isAuthenticated(r) {

		logEvent(
			"AUTH_FAILED",
			"Unauthorized secret access",
		)

		http.Error(
			w,
			"Unauthorized",
			http.StatusUnauthorized,
		)

		return
	}

	logEvent(
		"SECRETS_VIEW",
		"Secrets requested",
	)

	decryptedSecrets := make(
		[]Secret,
		0,
		len(secrets),
	)

	for _, secret := range secrets {

		encryptedValue, err := hex.DecodeString(
			secret.Value,
		)

		if err != nil {

			log.Printf(
				"[ERROR] Failed to decode secret '%s': %v",
				secret.Key,
				err,
			)

			http.Error(
				w,
				"Failed to decode secret",
				http.StatusInternalServerError,
			)

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

			http.Error(
				w,
				"Failed to decrypt secret",
				http.StatusInternalServerError,
			)

			return
		}

		decryptedSecrets = append(
			decryptedSecrets,
			Secret{
				Key:   secret.Key,
				Value: decryptedValue,
			},
		)
	}

	w.Header().Set(
		"Content-Type",
		"application/json",
	)

	json.NewEncoder(w).Encode(decryptedSecrets)
}

// API keys Delete Handler

func handleDeleteSecret(w http.ResponseWriter, r *http.Request) {

	if !isAuthenticated(r) {

		logEvent(
			"AUTH_FAILED",
			"Unauthorized delete attempt",
		)

		http.Error(
			w,
			"Unauthorized",
			http.StatusUnauthorized,
		)

		return
	}

	var data struct {
		Key string `json:"key"`
	}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {

		log.Printf(
			"[ERROR] Invalid delete JSON: %v",
			err,
		)

		http.Error(
			w,
			"Invalid JSON",
			http.StatusBadRequest,
		)

		return
	}

	for i, secret := range secrets {

		if secret.Key == data.Key {

			secrets = append(
				secrets[:i],
				secrets[i+1:]...,
			)

			if err := saveSecrets(secrets); err != nil {

				log.Printf(
					"[ERROR] Failed to delete secret '%s': %v",
					data.Key,
					err,
				)

				http.Error(
					w,
					"Failed to save secrets",
					http.StatusInternalServerError,
				)

				return
			}

			log.Printf(
				"[SECRET] Secret '%s' deleted",
				data.Key,
			)

			w.Header().Set(
				"Content-Type",
				"application/json",
			)

			json.NewEncoder(w).Encode(
				map[string]string{
					"status": "deleted",
				},
			)

			return
		}
	}

	log.Printf(
		"[SECRET] Delete failed: '%s' not found",
		data.Key,
	)

	http.Error(
		w,
		"Secret not found",
		http.StatusNotFound,
	)
}
