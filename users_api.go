package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// ================= USERS =================

func handleAPIUsers(w http.ResponseWriter, r *http.Request) {
	user, ok := requireUser(w, r)
	if !ok {
		return
	}

	// The user-management/share picker needs public user information only.
	// Password hashes must never be returned.
	rows, err := db.Query(`
		SELECT id, username, email, role, status
		FROM users
		ORDER BY username ASC
	`)
	if err != nil {
		log.Printf("[ERROR] Failed to load users: %v", err)
		http.Error(w, "Failed to load users", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	users := make([]APIUser, 0)

	for rows.Next() {
		var u APIUser

		if err := rows.Scan(
			&u.ID,
			&u.Username,
			&u.Email,
			&u.Role,
			&u.Status,
		); err != nil {
			log.Printf("[ERROR] Failed to scan user: %v", err)
			http.Error(w, "Failed to load users", http.StatusInternalServerError)
			return
		}

		users = append(users, u)
	}

	if err := rows.Err(); err != nil {
		log.Printf("[ERROR] Failed while reading users: %v", err)
		http.Error(w, "Failed to load users", http.StatusInternalServerError)
		return
	}

	_ = user // authenticated user is intentionally allowed to see public users

	jsonOut(w, users)
}

func handleCreateUser(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var user APIUser

	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	user.Username = strings.TrimSpace(user.Username)
	user.Email = strings.TrimSpace(user.Email)

	if user.Username == "" || user.Password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	hashed, err := hashPassword(user.Password)
	if err != nil {
		log.Printf("[ERROR] Failed to hash password: %v", err)
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	id, err := newID()
	if err != nil {
		log.Printf("[ERROR] Failed to generate user id: %v", err)
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	_, err = db.Exec(`
		INSERT INTO users (
			id,
			username,
			email,
			password_hash,
			role,
			status
		)
		VALUES (?, ?, ?, ?, ?, ?)
	`,
		id,
		user.Username,
		user.Email,
		hashed,
		"user",
		"active",
	)

	if err != nil {
		if isDuplicateError(err) {
			http.Error(
				w,
				"Username already taken",
				http.StatusConflict,
			)
			return
		}

		log.Printf("[ERROR] Failed to create user: %v", err)
		http.Error(
			w,
			"Failed to create user",
			http.StatusInternalServerError,
		)
		return
	}

	logEvent("USER_CREATED", "Account created: "+user.Username)

	jsonOut(w, map[string]string{
		"status": "created",
		"id":     id,
	})
}

func handleUserStatus(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var data struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	data.ID = strings.TrimSpace(data.ID)

	if data.ID == "" {
		http.Error(w, "User ID is required", http.StatusBadRequest)
		return
	}

	if data.Status != "active" && data.Status != "inactive" {
		http.Error(w, "Invalid status", http.StatusBadRequest)
		return
	}

	var (
		username string
		role     string
		status   string
	)

	err := db.QueryRow(`
		SELECT username, role, status
		FROM users
		WHERE id = ?
		LIMIT 1
	`, data.ID).Scan(
		&username,
		&role,
		&status,
	)

	if err == sql.ErrNoRows {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	if err != nil {
		log.Printf("[ERROR] Failed to load user status: %v", err)
		http.Error(w, "Failed to load user", http.StatusInternalServerError)
		return
	}

	// Prevent disabling the last active administrator.
	if data.Status == "inactive" &&
		role == "admin" &&
		status == "active" {

		var activeAdmins int

		err := db.QueryRow(`
			SELECT COUNT(*)
			FROM users
			WHERE role = 'admin'
			  AND status = 'active'
		`).Scan(&activeAdmins)

		if err != nil {
			log.Printf("[ERROR] Failed to count active admins: %v", err)
			http.Error(
				w,
				"Failed to validate administrator status",
				http.StatusInternalServerError,
			)
			return
		}

		if activeAdmins <= 1 {
			http.Error(
				w,
				"Cannot deactivate the last active admin",
				http.StatusConflict,
			)
			return
		}
	}

	_, err = db.Exec(`
		UPDATE users
		SET status = ?
		WHERE id = ?
	`, data.Status, data.ID)

	if err != nil {
		log.Printf("[ERROR] Failed to update user status: %v", err)
		http.Error(
			w,
			"Failed to update user",
			http.StatusInternalServerError,
		)
		return
	}

	// Immediately invalidate sessions when disabling an account.
	if data.Status == "inactive" {
		if err := dropSessionsForUser(data.ID); err != nil {
			log.Printf(
				"[ERROR] Failed to drop sessions for %s: %v",
				data.ID,
				err,
			)
		}
	}

	logEvent(
		"USER_STATUS_CHANGED",
		fmt.Sprintf("%s -> %s", username, data.Status),
	)

	jsonOut(w, map[string]string{
		"status": "updated",
	})
}

func handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var data struct {
		ID string `json:"id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	data.ID = strings.TrimSpace(data.ID)

	if data.ID == "" {
		http.Error(w, "User ID is required", http.StatusBadRequest)
		return
	}

	var (
		username string
		role     string
		status   string
	)

	err := db.QueryRow(`
		SELECT username, role, status
		FROM users
		WHERE id = ?
		LIMIT 1
	`, data.ID).Scan(
		&username,
		&role,
		&status,
	)

	if err == sql.ErrNoRows {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	if err != nil {
		log.Printf("[ERROR] Failed to load user: %v", err)
		http.Error(w, "Failed to load user", http.StatusInternalServerError)
		return
	}

	// Prevent deleting the last active administrator.
	if role == "admin" && status == "active" {
		var activeAdmins int

		err := db.QueryRow(`
			SELECT COUNT(*)
			FROM users
			WHERE role = 'admin'
			  AND status = 'active'
		`).Scan(&activeAdmins)

		if err != nil {
			log.Printf("[ERROR] Failed to count active admins: %v", err)
			http.Error(
				w,
				"Failed to validate administrator status",
				http.StatusInternalServerError,
			)
			return
		}

		if activeAdmins <= 1 {
			http.Error(
				w,
				"Cannot delete the last active admin",
				http.StatusConflict,
			)
			return
		}
	}

	// sessions, permissions, and owned secrets are removed automatically
	// through the foreign-key ON DELETE CASCADE rules.
	_, err = db.Exec(`
		DELETE FROM users
		WHERE id = ?
	`, data.ID)

	if err != nil {
		log.Printf("[ERROR] Failed to delete user: %v", err)
		http.Error(
			w,
			"Failed to delete user",
			http.StatusInternalServerError,
		)
		return
	}

	logEvent(
		"USER_DELETED",
		"Account removed: "+username,
	)

	jsonOut(w, map[string]string{
		"status": "deleted",
	})
}

// ================= SECRET ACCESS =================

// resolveSecretID resolves a secret from the request.
//
// New clients should send:
//
//	secret_id
//
// The old key parameter is still supported for compatibility.
func resolveSecretID(
	r *http.Request,
	user *APIUser,
) (int64, error) {

	secretIDRaw := strings.TrimSpace(
		r.URL.Query().Get("secret_id"),
	)

	if secretIDRaw != "" {
		var secretID int64

		if _, err := fmt.Sscanf(secretIDRaw, "%d", &secretID); err != nil {
			return 0, fmt.Errorf("invalid secret_id")
		}

		if secretID <= 0 {
			return 0, fmt.Errorf("invalid secret_id")
		}

		return secretID, nil
	}

	key := strings.TrimSpace(r.URL.Query().Get("key"))

	if key == "" {
		return 0, fmt.Errorf("secret_id or key is required")
	}

	var (
		secretID int64
		ownerID  string
	)

	var err error

	if isAdmin(user) {
		err = db.QueryRow(`
			SELECT id, created_by
			FROM secrets
			WHERE secret_key = ?
			ORDER BY id DESC
			LIMIT 1
		`, key).Scan(
			&secretID,
			&ownerID,
		)
	} else {
		err = db.QueryRow(`
			SELECT id, created_by
			FROM secrets
			WHERE secret_key = ?
			  AND created_by = ?
			LIMIT 1
		`, key, user.ID).Scan(
			&secretID,
			&ownerID,
		)
	}

	if err == sql.ErrNoRows {
		return 0, sql.ErrNoRows
	}

	if err != nil {
		return 0, err
	}

	return secretID, nil
}

func handleGetSecretAccess(w http.ResponseWriter, r *http.Request) {
	user, ok := requireUser(w, r)
	if !ok {
		return
	}

	secretID, err := resolveSecretID(r, user)

	if err == sql.ErrNoRows {
		http.Error(w, "Secret not found", http.StatusNotFound)
		return
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if !canAdministerSecret(user, secretID) {
		http.Error(
			w,
			"Not allowed to manage this secret",
			http.StatusForbidden,
		)
		return
	}

	permission := Permission{
		SecretID: secretID,
		UserIDs:  []string{},
	}

	rows, err := db.Query(`
		SELECT user_id
		FROM secret_permissions
		WHERE secret_id = ?
		ORDER BY user_id
	`, secretID)

	if err != nil {
		log.Printf(
			"[ERROR] Failed to load secret permissions: %v",
			err,
		)

		http.Error(
			w,
			"Failed to load permissions",
			http.StatusInternalServerError,
		)
		return
	}

	defer rows.Close()

	for rows.Next() {
		var userID string

		if err := rows.Scan(&userID); err != nil {
			log.Printf(
				"[ERROR] Failed to scan secret permission: %v",
				err,
			)

			http.Error(
				w,
				"Failed to load permissions",
				http.StatusInternalServerError,
			)
			return
		}

		permission.UserIDs = append(
			permission.UserIDs,
			userID,
		)
	}

	if err := rows.Err(); err != nil {
		log.Printf(
			"[ERROR] Failed reading secret permissions: %v",
			err,
		)

		http.Error(
			w,
			"Failed to load permissions",
			http.StatusInternalServerError,
		)
		return
	}

	jsonOut(w, permission)
}

func handleSaveSecretAccess(w http.ResponseWriter, r *http.Request) {
	user, ok := requireUser(w, r)
	if !ok {
		return
	}

	var permission Permission

	if err := json.NewDecoder(r.Body).Decode(&permission); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if permission.SecretID <= 0 {
		http.Error(
			w,
			"secret_id is required",
			http.StatusBadRequest,
		)
		return
	}

	if !canAdministerSecret(user, permission.SecretID) {
		logEvent(
			"ACCESS_DENIED",
			fmt.Sprintf(
				"User %s tried to change sharing for secret %d",
				user.Username,
				permission.SecretID,
			),
		)

		http.Error(
			w,
			"Not allowed to manage this secret",
			http.StatusForbidden,
		)
		return
	}

	if permission.UserIDs == nil {
		permission.UserIDs = []string{}
	}

	// Make sure the secret actually exists.
	var exists int

	err := db.QueryRow(`
		SELECT 1
		FROM secrets
		WHERE id = ?
		LIMIT 1
	`, permission.SecretID).Scan(&exists)

	if err == sql.ErrNoRows {
		http.Error(w, "Secret not found", http.StatusNotFound)
		return
	}

	if err != nil {
		log.Printf(
			"[ERROR] Failed to check secret: %v",
			err,
		)

		http.Error(
			w,
			"Failed to check secret",
			http.StatusInternalServerError,
		)
		return
	}

	tx, err := db.Begin()
	if err != nil {
		log.Printf(
			"[ERROR] Failed to begin permission transaction: %v",
			err,
		)

		http.Error(
			w,
			"Failed to save permissions",
			http.StatusInternalServerError,
		)
		return
	}

	defer tx.Rollback()

	// Replace the entire permission set atomically.
	if _, err := tx.Exec(`
		DELETE FROM secret_permissions
		WHERE secret_id = ?
	`, permission.SecretID); err != nil {

		log.Printf(
			"[ERROR] Failed to clear secret permissions: %v",
			err,
		)

		http.Error(
			w,
			"Failed to save permissions",
			http.StatusInternalServerError,
		)
		return
	}

	// Prevent duplicate user IDs from causing unnecessary INSERT errors.
	seen := make(map[string]struct{})

	for _, userID := range permission.UserIDs {
		userID = strings.TrimSpace(userID)

		if userID == "" {
			continue
		}

		if userID == user.ID {
			// The owner does not need a permission row for their own secret.
			continue
		}

		if _, exists := seen[userID]; exists {
			continue
		}

		seen[userID] = struct{}{}

		// Only allow sharing with existing users.
		var userExists int

		err := tx.QueryRow(`
			SELECT 1
			FROM users
			WHERE id = ?
			LIMIT 1
		`, userID).Scan(&userExists)

		if err == sql.ErrNoRows {
			continue
		}

		if err != nil {
			log.Printf(
				"[ERROR] Failed to validate user %s: %v",
				userID,
				err,
			)

			http.Error(
				w,
				"Failed to validate shared user",
				http.StatusInternalServerError,
			)
			return
		}

		if _, err := tx.Exec(`
			INSERT INTO secret_permissions (
				secret_id,
				user_id
			)
			VALUES (?, ?)
		`, permission.SecretID, userID); err != nil {

			log.Printf(
				"[ERROR] Failed to add permission for user %s: %v",
				userID,
				err,
			)

			http.Error(
				w,
				"Failed to save permissions",
				http.StatusInternalServerError,
			)
			return
		}
	}

	if err := tx.Commit(); err != nil {
		log.Printf(
			"[ERROR] Failed to commit permissions: %v",
			err,
		)

		http.Error(
			w,
			"Failed to save permissions",
			http.StatusInternalServerError,
		)
		return
	}

	jsonOut(w, map[string]string{
		"status": "saved",
	})
}

// ================= HELPERS =================

func jsonOut(w http.ResponseWriter, data interface{}) {
	w.Header().Set(
		"Content-Type",
		"application/json",
	)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("[ERROR] Failed to encode JSON response: %v", err)
	}
}

func jsonErr(
	w http.ResponseWriter,
	message string,
	status int,
) {
	w.Header().Set(
		"Content-Type",
		"application/json",
	)

	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(
		map[string]string{
			"error": message,
		},
	)
}

// ================= PASSWORDS =================

// hashPassword uses bcrypt instead of the old fast SHA-256 scheme.
func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword(
		[]byte(password),
		bcrypt.DefaultCost,
	)

	if err != nil {
		return "", err
	}

	return string(hash), nil
}

// legacySHA256 exists only so old accounts can be migrated if they still
// contain a legacy SHA-256 password hash.
func legacySHA256(password string) string {
	sum := sha256.Sum256([]byte(password))
	return hex.EncodeToString(sum[:])
}

func isLegacyHash(stored string) bool {
	if len(stored) != 64 {
		return false
	}

	_, err := hex.DecodeString(stored)
	return err == nil
}

// verifyPassword supports both the old SHA-256 format and bcrypt.
//
// If needsUpgrade is true, the caller should replace the legacy hash
// with a bcrypt hash after successful authentication.
func verifyPassword(
	stored string,
	supplied string,
) (ok bool, needsUpgrade bool) {

	if isLegacyHash(stored) {
		match := subtle.ConstantTimeCompare(
			[]byte(legacySHA256(supplied)),
			[]byte(stored),
		) == 1

		return match, match
	}

	err := bcrypt.CompareHashAndPassword(
		[]byte(stored),
		[]byte(supplied),
	)

	return err == nil, false
}

// ================= IDs =================

func newID() (string, error) {
	buf := make([]byte, 16)

	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf(
			"failed to generate id: %w",
			err,
		)
	}

	return hex.EncodeToString(buf), nil
}

// ================= DATABASE HELPERS =================

// isDuplicateError detects the MySQL duplicate-key error without
// coupling the rest of the application to a driver-specific type.
func isDuplicateError(err error) bool {
	if err == nil {
		return false
	}

	message := strings.ToLower(err.Error())

	return strings.Contains(message, "duplicate entry") ||
		strings.Contains(message, "duplicate key") ||
		strings.Contains(message, "1062")
}

// ================= ACCESS ROUTER =================

func handleSecretAccess(w http.ResponseWriter, r *http.Request) {
	switch r.Method {

	case http.MethodGet:
		handleGetSecretAccess(w, r)

	case http.MethodPost:
		handleSaveSecretAccess(w, r)

	default:
		http.Error(
			w,
			"Method not allowed",
			http.StatusMethodNotAllowed,
		)
	}
}

// ================= API ROUTES =================

func registerAPIs(mux *http.ServeMux) {

	// Users
	mux.HandleFunc(
		"/api/users",
		handleAPIUsers,
	)

	mux.HandleFunc(
		"/api/users/create",
		handleCreateUser,
	)

	mux.HandleFunc(
		"/api/users/status",
		handleUserStatus,
	)

	mux.HandleFunc(
		"/api/users/delete",
		handleDeleteUser,
	)

	// Secrets
	mux.HandleFunc(
		"/api/secrets",
		handleAPISecrets,
	)

	// Secret sharing
	mux.HandleFunc(
		"/api/secrets/access",
		handleSecretAccess,
	)
}
