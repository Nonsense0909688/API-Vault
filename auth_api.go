package main

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Login throttling. Without it the login endpoint will answer brute-force
// attempts as fast as bcrypt can run.
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
		attempts[key] = &attemptRecord{count: 1, first: time.Now()}
		return
	}

	record.count++
}

func clearFailures(key string) {
	attemptsMu.Lock()
	defer attemptsMu.Unlock()

	delete(attempts, key)
}

// ensureAdminAccount creates the configured admin on first start. This used to
// run inside the login handler, which meant an unauthenticated request could
// trigger account creation and a users.json write.
func ensureAdminAccount() error {
	usersMu.Lock()
	defer usersMu.Unlock()

	users, err := loadJSON[APIUser](usersFile)
	if err != nil {
		return err
	}

	for _, u := range users {
		if u.Username == config.Auth.AdminUsername {
			return nil
		}
	}

	hashed, err := hashPassword(config.Auth.AdminPassword)
	if err != nil {
		return err
	}

	id, err := newID()
	if err != nil {
		return err
	}

	users = append(users, APIUser{
		ID:       id,
		Username: config.Auth.AdminUsername,
		Email:    "admin@localhost",
		Password: hashed,
		Role:     "admin",
		Status:   "active",
	})

	if err := saveJSON(usersFile, users); err != nil {
		return err
	}

	logEvent("ADMIN_CREATED", "Default Admin account created")
	return nil
}

// upgradeStoredHash re-hashes a legacy SHA-256 entry with bcrypt after a
// successful login, so existing installs migrate without a password reset.
func upgradeStoredHash(userID, password string) {
	hashed, err := hashPassword(password)
	if err != nil {
		log.Printf("[ERROR] Failed to upgrade password hash: %v", err)
		return
	}

	usersMu.Lock()
	defer usersMu.Unlock()

	users, err := loadJSON[APIUser](usersFile)
	if err != nil {
		log.Printf("[ERROR] Failed to load users for hash upgrade: %v", err)
		return
	}

	for i := range users {
		if users[i].ID != userID {
			continue
		}

		// Re-check: another request may have upgraded it already.
		if !isLegacyHash(users[i].Password) {
			return
		}

		users[i].Password = hashed

		if err := saveJSON(usersFile, users); err != nil {
			log.Printf("[ERROR] Failed to save upgraded password hash: %v", err)
			return
		}

		logEvent("HASH_UPGRADED", "Password hash migrated to bcrypt for "+users[i].Username)
		return
	}
}

// Handles login.

func handleLoginPost(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	logEvent("LOGIN_ATTEMPT", "Login request received")

	var data struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		log.Printf("[ERROR] Invalid login JSON: %v", err)
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	data.Username = strings.TrimSpace(data.Username)
	throttleKey := clientIP(r) + "|" + strings.ToLower(data.Username)

	if throttled(throttleKey) {
		logEvent("AUTH_THROTTLED", "Too many failed logins for "+data.Username)
		http.Error(w, "Too many failed attempts, try again later", http.StatusTooManyRequests)
		return
	}

	users, err := loadJSON[APIUser](usersFile)

	if err != nil {
		log.Printf("[ERROR] Failed to load users: %v", err)
		http.Error(w, "Failed to load users", http.StatusInternalServerError)
		return
	}

	var user *APIUser

	for i := range users {
		if users[i].Username == data.Username {
			user = &users[i]
			break
		}
	}

	// One message and one code for every failure, so the response does not
	// say whether the username exists or the account is disabled.
	if user == nil {
		noteFailure(throttleKey)
		logEvent("AUTH_FAILED", "Unknown username")
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	valid, needsUpgrade := verifyPassword(user.Password, data.Password)

	if !valid {
		noteFailure(throttleKey)
		logEvent("AUTH_FAILED", "Invalid password for: "+user.Username)
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	if user.Status != "active" {
		noteFailure(throttleKey)
		logEvent("AUTH_FAILED", "Inactive user: "+user.Username)
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	if needsUpgrade {
		upgradeStoredHash(user.ID, data.Password)
	}

	clearFailures(throttleKey)

	// Create session
	sessionID, err := createSession()

	if err != nil {
		log.Printf("[ERROR] Failed to create session: %v", err)
		http.Error(w, "Failed to create session", 500)
		return
	}

	if err := storeSession(sessionID, Session{
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(sessionDuration),
	}); err != nil {
		log.Printf("[ERROR] Failed to save session: %v", err)
		http.Error(w, "Failed to save session", 500)
		return
	}

	setSessionCookie(w, sessionID)

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

// Handles logout.

func handleLogout(w http.ResponseWriter, r *http.Request) {

	cookie, err := r.Cookie("session")

	if err == nil {
		if err := dropSession(cookie.Value); err != nil {
			log.Printf("[ERROR] Failed to save sessions: %v", err)
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
