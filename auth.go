package main

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/http"
	"time"
)

const defaultSessionDuration = 24 * time.Hour

// sessionDuration is resolved from the config at startup; it stays at the
// default when the config omits or misstates it.
var sessionDuration = defaultSessionDuration

func initSessionDuration() {
	raw := config.Session.Duration
	if raw == "" {
		return
	}

	d, err := time.ParseDuration(raw)
	if err != nil {
		log.Printf("[WARN] Invalid session.duration %q, using %s: %v", raw, defaultSessionDuration, err)
		return
	}

	if d <= 0 {
		log.Printf("[WARN] session.duration must be positive, using %s", defaultSessionDuration)
		return
	}

	sessionDuration = d
}

// lookupSession resolves a cookie to a live session, dropping it if expired.
func lookupSession(r *http.Request) (Session, bool) {
	cookie, err := r.Cookie("session")
	if err != nil {
		return Session{}, false
	}

	sessionsMu.RLock()
	session, exists := sessions[cookie.Value]
	sessionsMu.RUnlock()

	if !exists {
		return Session{}, false
	}

	if time.Now().After(session.ExpiresAt) {
		sessionsMu.Lock()
		delete(sessions, cookie.Value)
		err := saveSessionsLocked()
		sessionsMu.Unlock()

		if err != nil {
			log.Printf("[ERROR] Failed to persist session expiry: %v", err)
		}

		logEvent("SESSION_EXPIRED", "Session has expired")
		return Session{}, false
	}

	return session, true
}

// Check if the request carries a valid session.
func isAuthenticated(r *http.Request) bool {
	_, ok := lookupSession(r)
	return ok
}

// Get the logged-in user's ID.
func getSessionUserID(r *http.Request) (string, bool) {
	session, ok := lookupSession(r)
	if !ok {
		return "", false
	}

	return session.UserID, true
}

// Create new session id for user.
func createSession() (string, error) {
	bytes := make([]byte, 32)

	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	return hex.EncodeToString(bytes), nil
}

func storeSession(sessionID string, session Session) error {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()

	sessions[sessionID] = session

	if err := saveSessionsLocked(); err != nil {
		delete(sessions, sessionID)
		return err
	}

	return nil
}

func dropSession(sessionID string) error {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()

	delete(sessions, sessionID)
	return saveSessionsLocked()
}

// Invalidate every session belonging to a user, used when the account is
// deleted or deactivated so an existing cookie cannot outlive the change.
func dropSessionsForUser(userID string) error {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()

	for id, session := range sessions {
		if session.UserID == userID {
			delete(sessions, id)
		}
	}

	return saveSessionsLocked()
}

func setSessionCookie(w http.ResponseWriter, sessionID string) {
	http.SetCookie(w, &http.Cookie{
		Name:  "session",
		Value: sessionID,
		Path:  "/",

		HttpOnly: true,
		Secure:   config.Session.SecureCookies,

		SameSite: http.SameSiteStrictMode,

		Expires: time.Now().Add(sessionDuration),
		MaxAge:  int(sessionDuration.Seconds()),
	})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:  "session",
		Value: "",
		Path:  "/",

		HttpOnly: true,
		Secure:   config.Session.SecureCookies,

		SameSite: http.SameSiteStrictMode,

		MaxAge: -1,
	})
}
