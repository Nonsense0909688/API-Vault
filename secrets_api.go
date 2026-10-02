package main

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
)

// ---------------------------------------------------------
// SAVE / UPDATE SECRET
// ---------------------------------------------------------

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

	// Always assign ownership from the logged-in user.
	data.CreatedBy = user.ID

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

	encryptedHex := hex.EncodeToString(encryptedValue)

	// Check whether THIS USER already has a secret
	// with this key.
	var existingID int64

	err = db.QueryRow(`
		SELECT id
		FROM secrets
		WHERE secret_key = ?
		AND created_by = ?
		LIMIT 1
	`, data.Key, user.ID).Scan(&existingID)

	if err == nil {
		// Existing secret -> update it.
		_, err = db.Exec(`
			UPDATE secrets
			SET secret_value = ?
			WHERE id = ?
			AND created_by = ?
		`,
			encryptedHex,
			existingID,
			user.ID,
		)

		if err != nil {
			log.Printf(
				"[ERROR] Failed to update secret '%s': %v",
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

		jsonOut(w, map[string]string{
			"status": "overridden",
		})

		return
	}

	if err != sql.ErrNoRows {
		log.Printf(
			"[ERROR] Failed to check existing secret: %v",
			err,
		)

		http.Error(
			w,
			"Database error",
			http.StatusInternalServerError,
		)
		return
	}

	// New secret.
	_, err = db.Exec(`
		INSERT INTO secrets (
			secret_key,
			secret_value,
			created_by
		)
		VALUES (?, ?, ?)
	`,
		data.Key,
		encryptedHex,
		user.ID,
	)

	if err != nil {
		log.Printf(
			"[ERROR] Failed to insert secret '%s': %v",
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

	jsonOut(w, map[string]string{
		"status": "saved",
	})
}

// ---------------------------------------------------------
// VIEW SECRETS
// ---------------------------------------------------------

func handleViewSecrets(w http.ResponseWriter, r *http.Request) {
	currentUser, ok := requireUser(w, r)
	if !ok {
		return
	}

	admin := isAdmin(currentUser)

	var rows *sql.Rows
	var err error

	if admin {
		// Admin sees everything.
		rows, err = db.Query(`
			SELECT
				id,
				secret_key,
				secret_value,
				created_by
			FROM secrets
			ORDER BY id DESC
		`)
	} else {
		// Normal users see:
		// 1. Their own secrets
		// 2. Secrets explicitly shared with them
		rows, err = db.Query(`
			SELECT DISTINCT
				s.id,
				s.secret_key,
				s.secret_value,
				s.created_by
			FROM secrets s
			LEFT JOIN secret_permissions p
				ON s.id = p.secret_id
			WHERE s.created_by = ?
			   OR p.user_id = ?
			ORDER BY s.id DESC
		`,
			currentUser.ID,
			currentUser.ID,
		)
	}

	if err != nil {
		log.Printf(
			"[ERROR] Failed to query secrets: %v",
			err,
		)

		http.Error(
			w,
			"Failed to load secrets",
			http.StatusInternalServerError,
		)
		return
	}

	defer rows.Close()

	result := make([]Secret, 0)

	for rows.Next() {
		var secret Secret

		if err := rows.Scan(
			&secret.ID,
			&secret.Key,
			&secret.Value,
			&secret.CreatedBy,
		); err != nil {
			log.Printf(
				"[ERROR] Failed to scan secret: %v",
				err,
			)

			http.Error(
				w,
				"Failed to load secrets",
				http.StatusInternalServerError,
			)
			return
		}

		// secret.Value is already encrypted in the database.
		// Send the encrypted value directly.
		result = append(result, Secret{
			ID:        secret.ID,
			Key:       secret.Key,
			Value:     secret.Value,
			CreatedBy: secret.CreatedBy,
		})
	}

	if err := rows.Err(); err != nil {
		log.Printf(
			"[ERROR] Secret query failed: %v",
			err,
		)

		http.Error(
			w,
			"Failed to load secrets",
			http.StatusInternalServerError,
		)
		return
	}

	jsonOut(w, result)
}

func handleSecretValue(w http.ResponseWriter, r *http.Request) {
	user, ok := requireUser(w, r)
	if !ok {
		return
	}

	secretID := r.URL.Query().Get("id")

	if secretID == "" {
		http.Error(w, "secret id is required", http.StatusBadRequest)
		return
	}

	var (
		id            int64
		encryptedText string
		createdBy     string
	)

	err := db.QueryRow(`
		SELECT
			id,
			secret_value,
			created_by
		FROM secrets
		WHERE id = ?
		LIMIT 1
	`, secretID).Scan(
		&id,
		&encryptedText,
		&createdBy,
	)

	if err == sql.ErrNoRows {
		http.Error(w, "Secret not found", http.StatusNotFound)
		return
	}

	if err != nil {
		log.Printf("[ERROR] Failed to load secret %s: %v", secretID, err)
		http.Error(w, "Failed to load secret", http.StatusInternalServerError)
		return
	}

	// Check ownership / sharing.
	if !isAdmin(user) && createdBy != user.ID {
		var exists bool

		err := db.QueryRow(`
			SELECT EXISTS(
				SELECT 1
				FROM secret_permissions
				WHERE secret_id = ?
				  AND user_id = ?
			)
		`, id, user.ID).Scan(&exists)

		if err != nil {
			log.Printf(
				"[ERROR] Failed to check secret permission: %v",
				err,
			)

			http.Error(
				w,
				"Failed to check permission",
				http.StatusInternalServerError,
			)
			return
		}

		if !exists {
			http.Error(
				w,
				"Forbidden",
				http.StatusForbidden,
			)
			return
		}
	}

	// Decode encrypted database value.
	encryptedValue, err := hex.DecodeString(encryptedText)
	if err != nil {
		log.Printf(
			"[ERROR] Failed to decode secret %d: %v",
			id,
			err,
		)

		http.Error(
			w,
			"Failed to decode secret",
			http.StatusInternalServerError,
		)
		return
	}

	// Decrypt ONLY this secret.
	value, err := decrypt(
		encryptionKey,
		encryptedValue,
	)

	if err != nil {
		log.Printf(
			"[ERROR] Failed to decrypt secret %d: %v",
			id,
			err,
		)

		http.Error(
			w,
			"Failed to decrypt secret",
			http.StatusInternalServerError,
		)
		return
	}

	jsonOut(w, map[string]interface{}{
		"id":    id,
		"value": value,
	})
}

// ---------------------------------------------------------
// DELETE SECRET
// ---------------------------------------------------------

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
		http.Error(
			w,
			"Secret key is required",
			http.StatusBadRequest,
		)
		return
	}

	var secretID int64
	var ownerID string

	err := db.QueryRow(`
		SELECT id, created_by
		FROM secrets
		WHERE secret_key = ?
		AND created_by = ?
		LIMIT 1
	`,
		data.Key,
		user.ID,
	).Scan(
		&secretID,
		&ownerID,
	)

	// Admin can delete another user's secret.
	if err == sql.ErrNoRows && isAdmin(user) {

		err = db.QueryRow(`
			SELECT id, created_by
			FROM secrets
			WHERE secret_key = ?
			LIMIT 1
		`,
			data.Key,
		).Scan(
			&secretID,
			&ownerID,
		)
	}

	if err == sql.ErrNoRows {
		http.Error(
			w,
			"Secret not found",
			http.StatusNotFound,
		)
		return
	}

	if err != nil {
		log.Printf(
			"[ERROR] Failed to find secret: %v",
			err,
		)

		http.Error(
			w,
			"Database error",
			http.StatusInternalServerError,
		)
		return
	}

	// Non-admins can only delete their own secret.
	if !isAdmin(user) && ownerID != user.ID {
		logEvent(
			"ACCESS_DENIED",
			"User "+user.Username+
				" tried to delete "+data.Key,
		)

		http.Error(
			w,
			"Not allowed to delete this secret",
			http.StatusForbidden,
		)
		return
	}

	// Permissions are automatically deleted because
	// secret_permissions uses ON DELETE CASCADE.
	_, err = db.Exec(`
		DELETE FROM secrets
		WHERE id = ?
	`,
		secretID,
	)

	if err != nil {
		log.Printf(
			"[ERROR] Failed to delete secret '%s': %v",
			data.Key,
			err,
		)

		http.Error(
			w,
			"Failed to delete secret",
			http.StatusInternalServerError,
		)
		return
	}

	jsonOut(w, map[string]string{
		"status": "deleted",
	})
}

// ---------------------------------------------------------
// API ROUTER
// ---------------------------------------------------------

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
