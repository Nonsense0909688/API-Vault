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

// html/template, not text/template: the templates interpolate values into
// HTML and into JavaScript string literals, and only html/template escapes
// per context. With text/template a username containing a quote or a <script>
// tag was injected verbatim into the page.
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

	if generatedPasswordNotice != "" {
		log.Printf("[SETUP] Created %s with a generated admin password: %s", configFile, generatedPasswordNotice)
		log.Printf("[SETUP] Log in as %q with that password and change it.", config.Auth.AdminUsername)
	}

	initStorage()
	initSessionDuration()

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

	secretsMu.RLock()
	secretCount := len(secrets)
	secretsMu.RUnlock()

	log.Printf(
		"[STORAGE] Loaded %d secrets",
		secretCount,
	)

	// Load sessions
	loaded, err := loadSessions()

	if err != nil {

		log.Fatalf(
			"[ERROR] Failed to load sessions: %v",
			err,
		)
	}

	sessionsMu.Lock()
	sessions = loaded
	sessionCount := len(sessions)
	sessionsMu.Unlock()

	log.Printf(
		"[STORAGE] Loaded %d sessions",
		sessionCount,
	)

	// The admin account is created at startup rather than on the first login
	// request, so an unauthenticated caller cannot trigger the write.
	if err := ensureAdminAccount(); err != nil {
		log.Fatalf("[ERROR] Failed to ensure admin account: %v", err)
	}

	// A dedicated mux instead of DefaultServeMux: nothing this process
	// imports can register a route behind our back.
	mux := http.NewServeMux()

	registerPages(mux)
	registerAPIs(mux)

	mux.HandleFunc("/save_secrets", handleSaveSecretKey)
	mux.HandleFunc("/view_secrets", handleViewSecrets)
	mux.HandleFunc("/remove_secrets", handleDeleteSecret)
	mux.HandleFunc("/login/post", handleLoginPost)
	mux.HandleFunc("/logout", handleLogout)

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
		log.Printf("[WARN] session.secure_cookies is off; the session cookie will also be sent over plain HTTP. Turn it on when serving over TLS.")
	}

	server := &http.Server{
		Addr:    addr,
		Handler: mux,

		// Bound how long a client can hold a connection open without
		// finishing a request.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil {

		log.Fatalf(
			"[ERROR] Server stopped: %v",
			err,
		)
	}
}
