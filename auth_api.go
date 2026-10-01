package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
)

// Handles post login diff between diff users with diff passwords.

func handleLoginPost(w http.ResponseWriter, r *http.Request) {

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

	users, err := loadJSON[APIUser](usersFile)

	if err != nil {
		log.Printf("[ERROR] Failed to load users: %v", err)
		http.Error(w, "Failed to load users", http.StatusInternalServerError)
		return
	}

	adminExists := false

	for _, u := range users {
		if u.Username == config.Auth.AdminUsername {
			adminExists = true
			break
		}
	}

	if !adminExists {
		admin := APIUser{
			ID:       newID(),
			Username: config.Auth.AdminUsername,
			Email:    "admin@localhost",
			Password: hashPassword(config.Auth.AdminPassword),
			Role:     "admin",
			Status:   "active",
		}

		users = append(users, admin)

		if err := saveJSON(usersFile, users); err != nil {
			log.Printf("[ERROR] Failed to create default admin: %v", err)
			http.Error(w, "Failed to create default admin", http.StatusInternalServerError)
			return
		}

		logEvent("ADMIN_CREATED", "Default Admin account created")
	}

	var user *APIUser

	for i := range users {
		if users[i].Username == data.Username {
			user = &users[i]
			break
		}
	}

	if user == nil {
		logEvent("AUTH_FAILED", "Unknown username")
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	if user.Status != "active" {
		logEvent("AUTH_FAILED", "Inactive user: "+user.Username)
		http.Error(w, "Account is inactive", http.StatusUnauthorized)
		return
	}

	if hashPassword(data.Password) != user.Password {
		logEvent("AUTH_FAILED", "Invalid password for: "+user.Username)
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Create session
	sessionID, err := createSession()

	if err != nil {
		log.Printf("[ERROR] Failed to create session: %v", err)
		http.Error(w, "Failed to create session", 500)
		return
	}

	sessions[sessionID] = Session{
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(sessionDuration),
	}

	if err := saveSessions(sessions); err != nil {

		log.Printf("[ERROR] Failed to save session: %v", err)

		delete(sessions, sessionID)

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

// Misc Function which is used somewhere

func requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	userID, ok := getSessionUserID(r)

	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}

	users, err := loadJSON[APIUser](usersFile)

	if err != nil {
		http.Error(w, "Failed to load users", 500)
		return false
	}

	for _, user := range users {
		if user.ID == userID {
			if user.Role != "admin" {
				http.Error(w, "Admin access required", http.StatusForbidden)
				return false
			}

			return true
		}
	}

	http.Error(w, "User not found", http.StatusUnauthorized)
	return false
}

// handles logout from accounts

func handleLogout(w http.ResponseWriter, r *http.Request) {

	cookie, err := r.Cookie("session")

	if err == nil {

		delete(sessions, cookie.Value)

		logEvent(
			"LOGOUT",
			"Session invalidated",
		)

		if err := saveSessions(sessions); err != nil {
			log.Printf("[ERROR] Failed to save sessions: %v", err)
		}
	}

	clearSessionCookie(w)

	http.Redirect(
		w,
		r,
		"/login",
		http.StatusSeeOther,
	)
}
