package main

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"
)

const sessionDuration = 24 * time.Hour

func isAuthenticated(r *http.Request) bool {
	cookie, err := r.Cookie("session")

	if err != nil {
		return false
	}

	expiry, exists := sessions[cookie.Value]

	if !exists {
		return false
	}

	if time.Now().After(expiry) {
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

func createSession() (string, error) {
	bytes := make([]byte, 32)

	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	return hex.EncodeToString(bytes), nil
}

func setSessionCookie(w http.ResponseWriter, sessionID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteStrictMode,

		Expires: time.Now().Add(sessionDuration),
		MaxAge:  int(sessionDuration.Seconds()),
	})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}
