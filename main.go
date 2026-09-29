package main

import (
	"log"
	"net/http"
)

func main() {

	log.SetFlags(
		log.Ldate |
			log.Ltime |
			log.Lmicroseconds,
	)

	logEvent(
		"STARTING",
		"API-Vault v1.0.0",
	)

	if err := loadEncryptionKey(); err != nil {
		log.Fatal(err)
	}

	// Load secrets
	if err := loadSecrets(); err != nil {

		log.Fatalf(
			"[ERROR] Failed to load secrets: %v",
			err,
		)
	}

	log.Printf(
		"[STORAGE] Loaded %d secrets",
		len(secrets),
	)

	// Load sessions
	var err error

	sessions, err = loadSessions()

	if err != nil {

		log.Fatalf(
			"[ERROR] Failed to load sessions: %v",
			err,
		)
	}

	log.Printf(
		"[STORAGE] Loaded %d sessions",
		len(sessions),
	)

	// Routes
	http.HandleFunc("/", handleRoot)

	http.HandleFunc(
		"/save_secrets",
		handleSaveSecretKey,
	)

	http.HandleFunc(
		"/view_secrets",
		handleViewSecrets,
	)

	http.HandleFunc(
		"/remove_secrets",
		handleDeleteSecret,
	)

	http.HandleFunc(
		"/login",
		handleLogin,
	)

	http.HandleFunc(
		"/login/post",
		handleLoginPost,
	)

	http.HandleFunc(
		"/logout",
		handleLogout,
	)

	logEvent(
		"SERVER",
		"Listening on http://localhost:3000",
	)

	if err := http.ListenAndServe(
		":3000",
		nil,
	); err != nil {

		log.Fatalf(
			"[ERROR] Server stopped: %v",
			err,
		)
	}
}
