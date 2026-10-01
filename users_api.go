package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"time"
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

	jsonOut(w, users)
}

func handleCreateUser(w http.ResponseWriter, r *http.Request) {

	if !isAuthenticated(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var user APIUser

	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if user.Username == "" || user.Password == "" {
		http.Error(w, "Username and password are required", 400)
		return
	}

	user.ID = newID()
	user.Password = hashPassword(user.Password)

	// Users created through this endpoint are normal users.
	user.Role = "user"
	user.Status = "active"

	users, err := loadJSON[APIUser](usersFile)

	if err != nil {
		http.Error(w, "Failed to load users", 500)
		return
	}

	users = append(users, user)

	if err := saveJSON(usersFile, users); err != nil {
		http.Error(w, "Failed to save user", 500)
		return
	}

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

	users, err := loadJSON[APIUser](usersFile)

	if err != nil {
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
		http.Error(w, "User not found", 404)
		return
	}

	if err := saveJSON(usersFile, users); err != nil {
		http.Error(w, "Failed to save users", 500)
		return
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

	users, err := loadJSON[APIUser](usersFile)

	if err != nil {
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
		http.Error(w, "User not found", 404)
		return
	}

	if err := saveJSON(usersFile, result); err != nil {
		http.Error(w, "Failed to save users", 500)
		return
	}

	users = result

	jsonOut(w, map[string]string{
		"status": "deleted",
	})
}

// ================= SECRET ACCESS =================

func handleGetSecretAccess(w http.ResponseWriter, r *http.Request) {

	if !isAuthenticated(r) {
		http.Error(w, "Unauthorized", 401)
		return
	}

	key := r.URL.Query().Get("key")

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

	if !isAuthenticated(r) {
		http.Error(w, "Unauthorized", 401)
		return
	}

	var permission Permission

	if err := json.NewDecoder(r.Body).Decode(&permission); err != nil {
		http.Error(w, "Invalid JSON", 400)
		return
	}

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

func ensureData() error {
	return os.MkdirAll("data", 0755)
}

func hashPassword(password string) string {

	hash := sha256.Sum256(
		[]byte(password),
	)

	return hex.EncodeToString(hash[:])
}

func newID() string {
	return time.Now().Format(
		"20060102150405.000000000",
	)
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

func registerAPIs() {

	// Users
	http.HandleFunc(
		"/api/users",
		handleAPIUsers,
	)

	http.HandleFunc(
		"/api/users/create",
		handleCreateUser,
	)

	http.HandleFunc(
		"/api/users/status",
		handleUserStatus,
	)

	http.HandleFunc(
		"/api/users/delete",
		handleDeleteUser,
	)

	// Secrets
	http.HandleFunc(
		"/api/secrets",
		handleAPISecrets,
	)

	// Sharing
	http.HandleFunc(
		"/api/secrets/access",
		handleSecretAccess,
	)
}
