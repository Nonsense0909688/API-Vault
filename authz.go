package main

import (
	"database/sql"
	"log"
	"net/http"
)

// ---------------------------------------------------------
// CURRENT USER
// ---------------------------------------------------------

// currentUser resolves the session cookie to the stored
// account record in MySQL.
func currentUser(r *http.Request) (*APIUser, bool) {

	userID, ok := getSessionUserID(r)

	if !ok {
		return nil, false
	}

	var user APIUser

	err := db.QueryRow(`
		SELECT
			id,
			username,
			email,
			password_hash,
			role,
			status
		FROM users
		WHERE id = ?
		LIMIT 1
	`,
		userID,
	).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.Password,
		&user.Role,
		&user.Status,
	)

	if err == sql.ErrNoRows {
		return nil, false
	}

	if err != nil {
		log.Printf(
			"[ERROR] Failed to load current user: %v",
			err,
		)

		return nil, false
	}

	// Account was deactivated while the session was still valid.
	if user.Status != "active" {
		return nil, false
	}

	return &user, true
}

// ---------------------------------------------------------
// REQUIRE USER
// ---------------------------------------------------------

func requireUser(
	w http.ResponseWriter,
	r *http.Request,
) (*APIUser, bool) {

	user, ok := currentUser(r)

	if !ok {
		http.Error(
			w,
			"Unauthorized",
			http.StatusUnauthorized,
		)

		return nil, false
	}

	return user, true
}

// ---------------------------------------------------------
// REQUIRE ADMIN
// ---------------------------------------------------------

func requireAdmin(
	w http.ResponseWriter,
	r *http.Request,
) bool {

	user, ok := requireUser(w, r)

	if !ok {
		return false
	}

	if user.Role != "admin" {
		http.Redirect(
			w,
			r,
			"/?error=admin_required",
			http.StatusSeeOther,
		)

		return false
	}

	return true
}

// ---------------------------------------------------------
// ADMIN CHECK
// ---------------------------------------------------------

func isAdmin(user *APIUser) bool {
	return user != nil && user.Role == "admin"
}

// ---------------------------------------------------------
// SECRET OWNER
// ---------------------------------------------------------

// secretOwner returns the creator ID of a secret.
//
// NOTE:
// Secret names are unique per owner, not globally.
// Therefore this function should only be used when the key
// is known to belong to a specific user.
//
// For operations involving a specific secret, prefer using
// the secret ID.
func secretOwner(key string) (string, bool) {

	var ownerID string

	err := db.QueryRow(`
		SELECT created_by
		FROM secrets
		WHERE secret_key = ?
		LIMIT 1
	`,
		key,
	).Scan(&ownerID)

	if err == sql.ErrNoRows {
		return "", false
	}

	if err != nil {
		log.Printf(
			"[ERROR] Failed to find secret owner: %v",
			err,
		)

		return "", false
	}

	return ownerID, true
}

// ---------------------------------------------------------
// SECRET ADMINISTRATION
// ---------------------------------------------------------

// canAdministerSecret reports whether the user may:
//   - delete a secret
//   - overwrite a secret
//   - modify sharing permissions
//
// Reading a shared secret does NOT grant these permissions.
//
// Only the owner and admins may administer a secret.
func canAdministerSecret(user *APIUser, secretID int64) bool {
	if user == nil {
		return false
	}

	// Admins can manage every secret.
	if user.Role == "admin" {
		return true
	}

	var ownerID string

	err := db.QueryRow(`
		SELECT created_by
		FROM secrets
		WHERE id = ?
		LIMIT 1
	`, secretID).Scan(&ownerID)

	if err != nil {
		if err != sql.ErrNoRows {
			log.Printf(
				"[ERROR] Failed to find secret owner for %d: %v",
				secretID,
				err,
			)
		}

		return false
	}

	return ownerID == user.ID
}
