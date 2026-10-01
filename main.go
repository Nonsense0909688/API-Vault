package main

import (
	"embed"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"text/template"
)

//go:embed templates
var templatesFS embed.FS

var templates = template.Must(
	template.ParseFS(templatesFS, "templates/*.html"),
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

	if err := loadConfig(); err != nil {
		log.Fatal(err)
	}

	initStorage()

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
	registerPages()
	registerAPIs()

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
		"/login/post",
		handleLoginPost,
	)

	http.HandleFunc(
		"/logout",
		handleLogout,
	)

	logEvent(
		"SERVER",
		fmt.Sprintf(
			"Listening on http://%s:%d",
			config.AppSettings.Address,
			config.AppSettings.Port,
		),
	)

	if err := http.ListenAndServe(
		net.JoinHostPort(
			config.AppSettings.Address,
			strconv.Itoa(config.AppSettings.Port),
		),
		nil,
	); err != nil {

		log.Fatalf(
			"[ERROR] Server stopped: %v",
			err,
		)
	}
}
