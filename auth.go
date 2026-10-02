package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"log"
	"net/http"
	"time"
)

const defaultSessionDuration = 24 * time.Hour

var sessionDuration = defaultSessionDuration

func initSessionDuration() {
	raw := config.Session.Duration

	if raw == "" {
		return
	}

	d, err := time.ParseDuration(raw)
	if err != nil {
		log.Printf(
			"[WARN] Invalid session.duration %q, using %s: %v",
			raw,
			defaultSessionDuration,
			err,
		)
		return
	}

	if d <= 0 {
		log.Printf(
			"[WARN] session.duration must be positive, using %s",
			defaultSessionDuration,
		)
		return
	}

	sessionDuration = d
}

// ---------------------------------------------------------
// LOOKUP SESSION
// ---------------------------------------------------------

// lookupSession resolves the session cookie using MySQL.
func lookupSession(r *http.Request) (Session, bool) {

	cookie, err := r.Cookie("session")
	if err != nil {
		return Session{}, false
	}

	var session Session

	err = db.QueryRow(`
		SELECT
			id,
			user_id,
			expires_at
		FROM sessions
		WHERE id = ?
		LIMIT 1
	`,
		cookie.Value,
	).Scan(
		&session.ID,
		&session.UserID,
		&session.ExpiresAt,
	)

	if err == sql.ErrNoRows {
		return Session{}, false
	}

	if err != nil {
		log.Printf(
			"[ERROR] Failed to lookup session: %v",
			err,
		)
		return Session{}, false
	}

	// Session expired.
	if time.Now().After(session.ExpiresAt) {

		if _, err := db.Exec(`
			DELETE FROM sessions
			WHERE id = ?
		`, session.ID); err != nil {

			log.Printf(
				"[ERROR] Failed to remove expired session: %v",
				err,
			)
		}

		logEvent(
			"SESSION_EXPIRED",
			"Session has expired",
		)

		return Session{}, false
	}

	return session, true
}

// ---------------------------------------------------------
// AUTHENTICATION
// ---------------------------------------------------------

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

// ---------------------------------------------------------
// SESSION ID
// ---------------------------------------------------------

func createSession() (string, error) {

	bytes := make([]byte, 32)

	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	return hex.EncodeToString(bytes), nil
}

// ---------------------------------------------------------
// STORE SESSION
// ---------------------------------------------------------

func storeSession(sessionID string, session Session) error {

	_, err := db.Exec(`
		INSERT INTO sessions (
			id,
			user_id,
			expires_at
		)
		VALUES (?, ?, ?)
	`,
		sessionID,
		session.UserID,
		session.ExpiresAt,
	)

	if err != nil {
		log.Printf(
			"[ERROR] Failed to store session: %v",
			err,
		)

		return err
	}

	return nil
}

// ---------------------------------------------------------
// DROP SESSION
// ---------------------------------------------------------

func dropSession(sessionID string) error {

	_, err := db.Exec(`
		DELETE FROM sessions
		WHERE id = ?
	`,
		sessionID,
	)

	if err != nil {
		log.Printf(
			"[ERROR] Failed to delete session: %v",
			err,
		)
	}

	return err
}

// ---------------------------------------------------------
// DROP ALL USER SESSIONS
// ---------------------------------------------------------

// Invalidate every session belonging to a user.
// Used when an account is deleted or deactivated.
func dropSessionsForUser(userID string) error {

	_, err := db.Exec(`
		DELETE FROM sessions
		WHERE user_id = ?
	`,
		userID,
	)

	if err != nil {
		log.Printf(
			"[ERROR] Failed to delete user sessions: %v",
			err,
		)
	}

	return err
}

// ---------------------------------------------------------
// SESSION COOKIE
// ---------------------------------------------------------

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
