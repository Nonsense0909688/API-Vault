package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
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

	if !isAuthenticated(r) {
		http.Error(w, "Unauthorized", 401)
		return
	}

	users, err := loadJSON[APIUser](usersFile)

	if err != nil {
		http.Error(w, "Failed to load users", 500)
		return
	}

	// Never hand out password hashes: the share picker only needs the id,
	// name and email, and an unsalted hash is cheap to crack offline.
	jsonOut(w, publicUsers(users))
}

func handleCreateUser(w http.ResponseWriter, r *http.Request) {

	// Creating accounts is an admin action. This used to accept any logged-in
	// user, so a regular account could mint more accounts at will.
	if !requireAdmin(w, r) {
		return
	}

	var user APIUser

	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	user.Username = strings.TrimSpace(user.Username)

	if user.Username == "" || user.Password == "" {
		http.Error(w, "Username and password are required", 400)
		return
	}

	hashed, err := hashPassword(user.Password)
	if err != nil {
		log.Printf("[ERROR] Failed to hash password: %v", err)
		http.Error(w, "Failed to create user", 500)
		return
	}

	id, err := newID()
	if err != nil {
		log.Printf("[ERROR] Failed to generate user id: %v", err)
		http.Error(w, "Failed to create user", 500)
		return
	}

	user.ID = id
	user.Password = hashed

	// Users created through this endpoint are normal users.
	user.Role = "user"
	user.Status = "active"

	usersMu.Lock()
	defer usersMu.Unlock()

	users, err := loadJSON[APIUser](usersFile)

	if err != nil {
		http.Error(w, "Failed to load users", 500)
		return
	}

	for _, existing := range users {
		if strings.EqualFold(existing.Username, user.Username) {
			http.Error(w, "Username already taken", http.StatusConflict)
			return
		}
	}

	users = append(users, user)

	if err := saveJSON(usersFile, users); err != nil {
		http.Error(w, "Failed to save user", 500)
		return
	}

	logEvent("USER_CREATED", "Account created: "+user.Username)

	jsonOut(w, map[string]string{
		"status": "created",
		"id":     user.ID,
	})
}

func handleUserStatus(w http.ResponseWriter, r *http.Request) {

	if !requireAdmin(w, r) {
		return
	}

	var data struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Invalid JSON", 400)
		return
	}

	if data.Status != "active" && data.Status != "inactive" {
		http.Error(w, "Invalid status", 400)
		return
	}

	usersMu.Lock()

	users, err := loadJSON[APIUser](usersFile)

	if err != nil {
		usersMu.Unlock()
		http.Error(w, "Failed to load users", 500)
		return
	}

	found := false

	for i := range users {

		if users[i].ID == data.ID {

			users[i].Status = data.Status
			found = true

			break
		}
	}

	if !found {
		usersMu.Unlock()
		http.Error(w, "User not found", 404)
		return
	}

	if data.Status == "inactive" && !hasActiveAdmin(users) {
		usersMu.Unlock()
		http.Error(w, "Cannot deactivate the last active admin", http.StatusConflict)
		return
	}

	if err := saveJSON(usersFile, users); err != nil {
		usersMu.Unlock()
		http.Error(w, "Failed to save users", 500)
		return
	}

	usersMu.Unlock()

	// A deactivated account must not keep working through an existing cookie.
	if data.Status == "inactive" {
		if err := dropSessionsForUser(data.ID); err != nil {
			log.Printf("[ERROR] Failed to drop sessions for %s: %v", data.ID, err)
		}
	}

	jsonOut(w, map[string]string{
		"status": "updated",
	})
}

func handleDeleteUser(w http.ResponseWriter, r *http.Request) {

	if !requireAdmin(w, r) {
		return
	}

	var data struct {
		ID string `json:"id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Invalid JSON", 400)
		return
	}

	usersMu.Lock()

	users, err := loadJSON[APIUser](usersFile)

	if err != nil {
		usersMu.Unlock()
		http.Error(w, "Failed to load users", 500)
		return
	}

	found := false
	result := make([]APIUser, 0, len(users))

	for _, user := range users {

		if user.ID == data.ID {
			found = true
			continue
		}

		result = append(result, user)
	}

	if !found {
		usersMu.Unlock()
		http.Error(w, "User not found", 404)
		return
	}

	if !hasActiveAdmin(result) {
		usersMu.Unlock()
		http.Error(w, "Cannot delete the last active admin", http.StatusConflict)
		return
	}

	if err := saveJSON(usersFile, result); err != nil {
		usersMu.Unlock()
		http.Error(w, "Failed to save users", 500)
		return
	}

	usersMu.Unlock()

	if err := dropSessionsForUser(data.ID); err != nil {
		log.Printf("[ERROR] Failed to drop sessions for %s: %v", data.ID, err)
	}

	logEvent("USER_DELETED", "Account removed: "+data.ID)

	jsonOut(w, map[string]string{
		"status": "deleted",
	})
}

func hasActiveAdmin(users []APIUser) bool {
	for _, user := range users {
		if user.Role == "admin" && user.Status == "active" {
			return true
		}
	}
	return false
}

// ================= SECRET ACCESS =================

func handleGetSecretAccess(w http.ResponseWriter, r *http.Request) {

	user, ok := requireUser(w, r)
	if !ok {
		return
	}

	key := r.URL.Query().Get("key")

	// Who a secret is shared with is only the owner's and an admin's business.
	if !canAdministerSecret(user, key) {
		http.Error(w, "Not allowed to manage this secret", http.StatusForbidden)
		return
	}

	permissions, err := loadJSON[Permission](permissionsFile)

	if err != nil {
		http.Error(w, "Failed to load permissions", 500)
		return
	}

	for _, permission := range permissions {

		if permission.Key == key {
			jsonOut(w, permission)
			return
		}
	}

	jsonOut(w, Permission{
		Key:     key,
		UserIDs: []string{},
	})
}

func handleSaveSecretAccess(w http.ResponseWriter, r *http.Request) {

	user, ok := requireUser(w, r)
	if !ok {
		return
	}

	var permission Permission

	if err := json.NewDecoder(r.Body).Decode(&permission); err != nil {
		http.Error(w, "Invalid JSON", 400)
		return
	}

	if permission.Key == "" {
		http.Error(w, "Secret key is required", 400)
		return
	}

	// This endpoint decides who may read a secret. Without an ownership check
	// any logged-in user could grant themselves access to every entry in the
	// vault, which defeats the per-user model entirely.
	if !canAdministerSecret(user, permission.Key) {
		logEvent("ACCESS_DENIED", "User "+user.Username+" tried to change sharing for "+permission.Key)
		http.Error(w, "Not allowed to manage this secret", http.StatusForbidden)
		return
	}

	if permission.UserIDs == nil {
		permission.UserIDs = []string{}
	}

	permissionsMu.Lock()
	defer permissionsMu.Unlock()

	permissions, err := loadJSON[Permission](permissionsFile)

	if err != nil {
		http.Error(w, "Failed to load permissions", 500)
		return
	}

	for i := range permissions {

		if permissions[i].Key != permission.Key {
			continue
		}

		permissions[i] = permission

		if err := saveJSON(
			permissionsFile,
			permissions,
		); err != nil {

			http.Error(
				w,
				"Failed to save permissions",
				500,
			)

			return
		}

		jsonOut(w, map[string]string{
			"status": "updated",
		})

		return
	}

	permissions = append(
		permissions,
		permission,
	)

	if err := saveJSON(
		permissionsFile,
		permissions,
	); err != nil {

		http.Error(
			w,
			"Failed to save permissions",
			500,
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

	json.NewEncoder(w).Encode(data)
}

func jsonErr(
	w http.ResponseWriter,
	message string,
	status int,
) {
	http.Error(w, message, status)
}

// hashPassword derives a bcrypt hash. The previous implementation was a bare
// unsalted SHA-256, which is fast enough to brute-force a leaked hash offline
// and identical for identical passwords across accounts.
func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

// legacySHA256 reproduces the old hash so existing users.json files still
// authenticate; see verifyPassword.
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

// verifyPassword checks a password against either hash format. It reports
// whether the stored hash is the old format and should be upgraded.
func verifyPassword(stored, supplied string) (ok bool, needsUpgrade bool) {
	if isLegacyHash(stored) {
		match := subtle.ConstantTimeCompare(
			[]byte(legacySHA256(supplied)),
			[]byte(stored),
		) == 1

		return match, match
	}

	err := bcrypt.CompareHashAndPassword([]byte(stored), []byte(supplied))
	return err == nil, false
}

// newID returns an unguessable identifier. The old version used a timestamp,
// which is predictable and collides when two accounts are created in the same
// nanosecond tick.
func newID() (string, error) {
	buf := make([]byte, 16)

	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("failed to generate id: %w", err)
	}

	return hex.EncodeToString(buf), nil
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
	mux.HandleFunc("/api/users", handleAPIUsers)
	mux.HandleFunc("/api/users/create", handleCreateUser)
	mux.HandleFunc("/api/users/status", handleUserStatus)
	mux.HandleFunc("/api/users/delete", handleDeleteUser)

	// Secrets
	mux.HandleFunc("/api/secrets", handleAPISecrets)

	// Sharing
	mux.HandleFunc("/api/secrets/access", handleSecretAccess)
}
