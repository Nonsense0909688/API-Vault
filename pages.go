package main

import (
	"fmt"
	"log"
	"net/http"
)

func handleLoginPage(w http.ResponseWriter, r *http.Request) {
	logEvent("LOGIN_PAGE", "Login page requested")

	if err := templates.ExecuteTemplate(w, "login.html", nil); err != nil {
		log.Printf("[ERROR] Failed to execute login template: %v", err)
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

func handleDashboardPage(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		logEvent("AUTH_FAILED", "Unauthorized access to dashboard")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	logEvent("DASHBOARD", "Dashboard accessed")

	if err := templates.ExecuteTemplate(w, "dashboard.html", nil); err != nil {
		log.Printf("[ERROR] Failed to execute index template: %v", err)
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

func getSession(r *http.Request) (*Session, *APIUser, error) {
	cookie, err := r.Cookie("session")
	if err != nil {
		return nil, nil, err
	}

	sessions, err := loadSessions()
	if err != nil {
		return nil, nil, err
	}

	session, exists := sessions[cookie.Value]
	if !exists {
		return nil, nil, fmt.Errorf("session not found")
	}

	users, err := loadJSON[APIUser](usersFile)
	if err != nil {
		return nil, nil, err
	}

	for i := range users {
		if users[i].ID == session.UserID {
			return &session, &users[i], nil
		}
	}

	return nil, nil, fmt.Errorf("user not found")
}
func handlekeysPage(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		logEvent("AUTH_FAILED", "Unauthorized access to keys")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	_, user, err := getSession(r)
	if err != nil {
		log.Printf("[ERROR] Failed to get session user: %v", err)
		http.Error(w, "Session error", http.StatusInternalServerError)
		return
	}

	data := struct {
		Username string
	}{
		Username: user.Username,
	}

	if err := templates.ExecuteTemplate(w, "keys.html", data); err != nil {
		log.Printf("[ERROR] Failed to execute keys template: %v", err)
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

func handleHistroyPage(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		logEvent("AUTH_FAILED", "Unauthorized access to dashboard")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if err := templates.ExecuteTemplate(w, "history.html", nil); err != nil {
		log.Printf("[ERROR] Failed to execute index template: %v", err)
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

func handleUserManagmentPage(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		logEvent("AUTH_FAILED", "Unauthorized access to dashboard")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if err := templates.ExecuteTemplate(w, "user_management.html", nil); err != nil {
		log.Printf("[ERROR] Failed to execute index template: %v", err)
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

func registerPages() {
	http.HandleFunc("/", handleDashboardPage)
	http.HandleFunc("/login", handleLoginPage)
	http.HandleFunc("/keys", handlekeysPage)
	http.HandleFunc("/user-management", handleUserManagmentPage)
	http.HandleFunc("/history", handleHistroyPage)
}
