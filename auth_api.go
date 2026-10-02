package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------
// LOGIN THROTTLING
// ---------------------------------------------------------

const (
	maxFailedAttempts = 10
	lockoutWindow     = 15 * time.Minute
)

type attemptRecord struct {
	count int
	first time.Time
}

var (
	attemptsMu sync.Mutex
	attempts   = map[string]*attemptRecord{}
)

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)

	if err != nil {
		return r.RemoteAddr
	}

	return host
}

func throttled(key string) bool {
	attemptsMu.Lock()
	defer attemptsMu.Unlock()

	record, ok := attempts[key]

	if !ok {
		return false
	}

	if time.Since(record.first) > lockoutWindow {
		delete(attempts, key)
		return false
	}

	return record.count >= maxFailedAttempts
}

func noteFailure(key string) {
	attemptsMu.Lock()
	defer attemptsMu.Unlock()

	record, ok := attempts[key]

	if !ok || time.Since(record.first) > lockoutWindow {
		attempts[key] = &attemptRecord{
			count: 1,
			first: time.Now(),
		}
		return
	}

	record.count++
}

func clearFailures(key string) {
	attemptsMu.Lock()
	defer attemptsMu.Unlock()

	delete(attempts, key)
}

// ---------------------------------------------------------
// ADMIN ACCOUNT
// ---------------------------------------------------------

func ensureAdminAccount() error {

	var existingID string

	err := db.QueryRow(`
		SELECT id
		FROM users
		WHERE username = ?
		LIMIT 1
	`,
		config.Auth.AdminUsername,
	).Scan(&existingID)

	// Admin already exists.
	if err == nil {
		return nil
	}

	if err != sql.ErrNoRows {
		return err
	}

	hashed, err := hashPassword(
		config.Auth.AdminPassword,
	)

	if err != nil {
		return err
	}

	id, err := newID()

	if err != nil {
		return err
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
		config.Auth.AdminUsername,
		"admin@localhost",
		hashed,
		"admin",
		"active",
	)

	if err != nil {
		return err
	}

	logEvent(
		"ADMIN_CREATED",
		"Default Admin account created",
	)

	return nil
}

// ---------------------------------------------------------
// PASSWORD HASH UPGRADE
// ---------------------------------------------------------

// Re-hashes a legacy SHA-256 password with bcrypt after
// successful login.
func upgradeStoredHash(userID, password string) {

	hashed, err := hashPassword(password)

	if err != nil {
		log.Printf(
			"[ERROR] Failed to upgrade password hash: %v",
			err,
		)
		return
	}

	var currentHash string
	var username string

	err = db.QueryRow(`
		SELECT
			username,
			password_hash
		FROM users
		WHERE id = ?
		LIMIT 1
	`,
		userID,
	).Scan(
		&username,
		&currentHash,
	)

	if err != nil {
		log.Printf(
			"[ERROR] Failed to load password hash for upgrade: %v",
			err,
		)
		return
	}

	// Another request may already have upgraded it.
	if !isLegacyHash(currentHash) {
		return
	}

	_, err = db.Exec(`
		UPDATE users
		SET password_hash = ?
		WHERE id = ?
	`,
		hashed,
		userID,
	)

	if err != nil {
		log.Printf(
			"[ERROR] Failed to save upgraded password hash: %v",
			err,
		)
		return
	}

	logEvent(
		"HASH_UPGRADED",
		"Password hash migrated to bcrypt for "+username,
	)
}

// ---------------------------------------------------------
// LOGIN
// ---------------------------------------------------------

func handleLoginPost(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Error(
			w,
			"Method not allowed",
			http.StatusMethodNotAllowed,
		)
		return
	}

	logEvent(
		"LOGIN_ATTEMPT",
		"Login request received",
	)

	var data struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

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

	data.Username = strings.TrimSpace(data.Username)

	throttleKey :=
		clientIP(r) +
			"|" +
			strings.ToLower(data.Username)

	if throttled(throttleKey) {

		logEvent(
			"AUTH_THROTTLED",
			"Too many failed logins for "+data.Username,
		)

		http.Error(
			w,
			"Too many failed attempts, try again later",
			http.StatusTooManyRequests,
		)

		return
	}

	// -----------------------------------------------------
	// Load user from MySQL
	// -----------------------------------------------------

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
		WHERE username = ?
		LIMIT 1
	`,
		data.Username,
	).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.Password,
		&user.Role,
		&user.Status,
	)

	// Same response for nonexistent users and invalid
	// passwords to avoid username enumeration.
	if err == sql.ErrNoRows {

		noteFailure(throttleKey)

		logEvent(
			"AUTH_FAILED",
			"Unknown username",
		)

		http.Error(
			w,
			"Invalid username or password",
			http.StatusUnauthorized,
		)

		return
	}

	if err != nil {

		log.Printf(
			"[ERROR] Failed to load user: %v",
			err,
		)

		http.Error(
			w,
			"Failed to load user",
			http.StatusInternalServerError,
		)

		return
	}

	// -----------------------------------------------------
	// Verify password
	// -----------------------------------------------------

	valid, needsUpgrade := verifyPassword(
		user.Password,
		data.Password,
	)

	if !valid {

		noteFailure(throttleKey)

		logEvent(
			"AUTH_FAILED",
			"Invalid password for: "+user.Username,
		)

		http.Error(
			w,
			"Invalid username or password",
			http.StatusUnauthorized,
		)

		return
	}

	// -----------------------------------------------------
	// Check account status
	// -----------------------------------------------------

	if user.Status != "active" {

		noteFailure(throttleKey)

		logEvent(
			"AUTH_FAILED",
			"Inactive user: "+user.Username,
		)

		http.Error(
			w,
			"Invalid username or password",
			http.StatusUnauthorized,
		)

		return
	}

	// Upgrade old SHA-256 hash to bcrypt.
	if needsUpgrade {
		upgradeStoredHash(
			user.ID,
			data.Password,
		)
	}

	clearFailures(throttleKey)

	// -----------------------------------------------------
	// Create session
	// -----------------------------------------------------

	sessionID, err := createSession()

	if err != nil {

		log.Printf(
			"[ERROR] Failed to create session: %v",
			err,
		)

		http.Error(
			w,
			"Failed to create session",
			http.StatusInternalServerError,
		)

		return
	}

	session := Session{
		ID:        sessionID,
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(sessionDuration),
	}

	if err := storeSession(
		sessionID,
		session,
	); err != nil {

		log.Printf(
			"[ERROR] Failed to save session: %v",
			err,
		)

		http.Error(
			w,
			"Failed to save session",
			http.StatusInternalServerError,
		)

		return
	}

	setSessionCookie(
		w,
		sessionID,
	)

	logEvent(
		"LOGIN_SUCCESS",
		"User "+user.Username+" logged in",
	)

	http.Redirect(
		w,
		r,
		"/",
		http.StatusSeeOther,
	)
}

// ---------------------------------------------------------
// LOGOUT
// ---------------------------------------------------------

func handleLogout(w http.ResponseWriter, r *http.Request) {

	cookie, err := r.Cookie("session")

	if err == nil {

		if err := dropSession(cookie.Value); err != nil {

			log.Printf(
				"[ERROR] Failed to delete session: %v",
				err,
			)
		}

		logEvent(
			"LOGOUT",
			"Session invalidated",
		)
	}

	clearSessionCookie(w)

	http.Redirect(
		w,
		r,
		"/login",
		http.StatusSeeOther,
	)
}

// Keep crypto/rand referenced if newID/createSession
// isn't the only random ID generator in this package.
var _ = rand.Reader
