package main

import (
	"log"
	"net/http"
)

func handleLoginPage(w http.ResponseWriter, r *http.Request) {
	logEvent("LOGIN_PAGE", "Login page requested")

	render(w, "login.html", nil)
}

func handleDashboardPage(w http.ResponseWriter, r *http.Request) {
	// "/" is the catch-all pattern, so without this every unknown path
	// rendered the dashboard instead of a 404.
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	if !isAuthenticated(r) {
		logEvent("AUTH_FAILED", "Unauthorized access to dashboard")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	logEvent("DASHBOARD", "Dashboard accessed")

	render(w, "dashboard.html", nil)
}

func handlekeysPage(w http.ResponseWriter, r *http.Request) {
	user, ok := currentUser(r)
	if !ok {
		logEvent("AUTH_FAILED", "Unauthorized access to keys")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	data := struct {
		Username string
	}{
		Username: user.Username,
	}

	render(w, "keys.html", data)
}

func handleUserManagmentPage(w http.ResponseWriter, r *http.Request) {
	user, ok := currentUser(r)
	if !ok {
		logEvent("AUTH_FAILED", "Unauthorized access to user management")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// The page drives the admin-only user endpoints, so it should not be
	// reachable by a regular account.
	if !isAdmin(user) {
		logEvent("ACCESS_DENIED", "Non-admin opened user management: "+user.Username)
		http.Redirect(w, r, "/?error=admin_required", http.StatusSeeOther)
		return
	}

	render(w, "user_management.html", nil)
}

func render(w http.ResponseWriter, name string, data any) {
	if err := templates.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("[ERROR] Failed to execute %s: %v", name, err)
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

func registerPages(mux *http.ServeMux) {
	mux.HandleFunc("/", handleDashboardPage)
	mux.HandleFunc("/login", handleLoginPage)
	mux.HandleFunc("/keys", handlekeysPage)
	mux.HandleFunc("/user-management", handleUserManagmentPage)

	// "/history" was registered but templates/history.html does not exist,
	// so the route always returned a 500. Removed until the page is built.
}
