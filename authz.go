package main

import (
	"log"
	"net/http"
)

// currentUser resolves the session cookie to the stored account record.
func currentUser(r *http.Request) (*APIUser, bool) {
	userID, ok := getSessionUserID(r)
	if !ok {
		return nil, false
	}

	users, err := loadJSON[APIUser](usersFile)
	if err != nil {
		log.Printf("[ERROR] Failed to load users: %v", err)
		return nil, false
	}

	for i := range users {
		if users[i].ID == userID {
			// An account deactivated mid-session stops counting immediately.
			if users[i].Status != "active" {
				return nil, false
			}

			return &users[i], true
		}
	}

	return nil, false
}

// requireUser is currentUser plus the 401 for handlers that need an account.
func requireUser(w http.ResponseWriter, r *http.Request) (*APIUser, bool) {
	user, ok := currentUser(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return nil, false
	}

	return user, true
}

// requireAdmin gates admin-only handlers.
func requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	user, ok := requireUser(w, r)
	if !ok {
		return false
	}

	if user.Role != "admin" {
		http.Error(w, "Admin access required", http.StatusForbidden)
		return false
	}

	return true
}

func isAdmin(user *APIUser) bool {
	return user != nil && user.Role == "admin"
}

// secretOwner returns the creator id of a stored secret.
func secretOwner(key string) (string, bool) {
	secretsMu.RLock()
	defer secretsMu.RUnlock()

	for _, secret := range secrets {
		if secret.Key == key {
			return secret.CreatedBy, true
		}
	}

	return "", false
}

// canAdministerSecret reports whether the user may delete a secret, overwrite
// it, or change who it is shared with. Being able to *read* a shared secret
// does not grant any of that — only the creator and admins qualify.
func canAdministerSecret(user *APIUser, key string) bool {
	if isAdmin(user) {
		return true
	}

	owner, exists := secretOwner(key)
	if !exists {
		// Nothing stored under that key yet, so there is no one to protect.
		return true
	}

	return owner == user.ID
}
