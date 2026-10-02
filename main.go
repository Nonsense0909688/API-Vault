package main

import (
	"embed"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"
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

	// ---------------------------------------------------------
	// CONFIG
	// ---------------------------------------------------------

	if err := loadConfig(); err != nil {
		log.Fatal(err)
	}

	if generatedPasswordNotice != "" {
		log.Printf(
			"[SETUP] Created %s with a generated admin password: %s",
			configFile,
			generatedPasswordNotice,
		)

		log.Printf(
			"[SETUP] Log in as %q with that password and change it.",
			config.Auth.AdminUsername,
		)
	}

	initSessionDuration()

	// ---------------------------------------------------------
	// ENCRYPTION
	// ---------------------------------------------------------

	if err := loadEncryptionKey(); err != nil {
		log.Fatal(err)
	}

	// ---------------------------------------------------------
	// DATABASE
	// ---------------------------------------------------------

	if err := initDB(); err != nil {
		log.Fatalf(
			"[ERROR] Failed to initialize MySQL: %v",
			err,
		)
	}

	defer db.Close()

	log.Println("[DB] MySQL initialized successfully")

	// ---------------------------------------------------------
	// ADMIN
	// ---------------------------------------------------------

	// Create the admin account at startup.
	// This prevents an unauthenticated request from triggering
	// account creation.
	if err := ensureAdminAccount(); err != nil {
		log.Fatalf(
			"[ERROR] Failed to ensure admin account: %v",
			err,
		)
	}

	// ---------------------------------------------------------
	// ROUTES
	// ---------------------------------------------------------

	mux := http.NewServeMux()

	registerPages(mux)
	registerAPIs(mux)

	// Legacy / direct endpoints
	mux.HandleFunc(
		"/save_secrets",
		handleSaveSecretKey,
	)

	mux.HandleFunc(
		"/view_secrets",
		handleViewSecrets,
	)

	mux.HandleFunc(
		"/remove_secrets",
		handleDeleteSecret,
	)

	mux.HandleFunc(
		"/login/post",
		handleLoginPost,
	)

	mux.HandleFunc(
		"/logout",
		handleLogout,
	)

	mux.HandleFunc("/api/secrets/value", handleSecretValue)

	// ---------------------------------------------------------
	// SERVER
	// ---------------------------------------------------------

	addr := net.JoinHostPort(
		config.AppSettings.Address,
		strconv.Itoa(config.AppSettings.Port),
	)

	logEvent(
		"SERVER",
		fmt.Sprintf(
			"Listening on http://%s",
			addr,
		),
	)

	if !config.Session.SecureCookies {
		log.Printf(
			"[WARN] session.secure_cookies is off; " +
				"the session cookie will also be sent over plain HTTP. " +
				"Enable it when serving over TLS.",
		)
	}

	server := &http.Server{
		Addr:    addr,
		Handler: mux,

		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	logEvent(
		"SERVER",
		"API-Vault is ready",
	)

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf(
			"[ERROR] Server stopped: %v",
			err,
		)
	}
}
