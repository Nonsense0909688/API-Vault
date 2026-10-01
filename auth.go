package main

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"
)

const sessionDuration = 24 * time.Hour

// Check if provided user id is authenticated

func isAuthenticated(r *http.Request) bool {

	cookie, err := r.Cookie("session")
	if err != nil {
		return false
	}

	session, exists := sessions[cookie.Value]

	if !exists {
		return false
	}

	if time.Now().After(session.ExpiresAt) {

		delete(sessions, cookie.Value)
		saveSessions(sessions)

		logEvent(
			"SESSION_EXPIRED",
			"Session has expired",
		)

		return false
	}

	return true
}

// Get the logged-in user's ID

func getSessionUserID(r *http.Request) (string, bool) {

	cookie, err := r.Cookie("session")

	if err != nil {
		return "", false
	}

	session, exists := sessions[cookie.Value]

	if !exists {
		return "", false
	}

	if time.Now().After(session.ExpiresAt) {

		delete(sessions, cookie.Value)
		saveSessions(sessions)

		logEvent(
			"SESSION_EXPIRED",
			"Session has expired",
		)

		return "", false
	}

	return session.UserID, true
}

// Create new session id for user

func createSession() (string, error) {

	bytes := make([]byte, 32)

	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	return hex.EncodeToString(bytes), nil
}

// Changing session cookie based on username and password used.

func setSessionCookie(w http.ResponseWriter, sessionID string) {

	http.SetCookie(w, &http.Cookie{
		Name:  "session",
		Value: sessionID,
		Path:  "/",

		HttpOnly: true,

		// Set true when using HTTPS.
		Secure: false,

		SameSite: http.SameSiteStrictMode,

		Expires: time.Now().Add(sessionDuration),
		MaxAge:  int(sessionDuration.Seconds()),
	})
}

// AT last clearing session cookie

func clearSessionCookie(w http.ResponseWriter) {

	http.SetCookie(w, &http.Cookie{
		Name:  "session",
		Value: "",
		Path:  "/",

		HttpOnly: true,
		Secure:   false,

		SameSite: http.SameSiteStrictMode,

		MaxAge: -1,
	})
}
