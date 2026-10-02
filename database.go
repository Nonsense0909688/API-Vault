package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

var db *sql.DB

func initDB() error {
	// Keep the existing config structure.
	// SQLite stores everything in one local database file.
	appFolder := config.Storage.AppFolder

	if appFolder == "" {
		appFolder = "appdata"
	}

	if err := os.MkdirAll(appFolder, 0700); err != nil {
		return fmt.Errorf("failed to create database directory: %w", err)
	}

	dbPath := filepath.Join(appFolder, "apivault.db")

	var err error

	db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("failed to open SQLite database: %w", err)
	}

	// API-Vault is a small self-hosted application.
	// Using one connection avoids SQLite "database is locked"
	// problems when multiple handlers write at the same time.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if err := db.Ping(); err != nil {
		db.Close()
		return fmt.Errorf("failed to connect to SQLite: %w", err)
	}

	// Enable foreign-key constraints.
	if _, err := db.Exec(`PRAGMA foreign_keys = ON`); err != nil {
		db.Close()
		return fmt.Errorf("failed to enable SQLite foreign keys: %w", err)
	}

	log.Printf("[DB] Connected to SQLite: %s", dbPath)

	if err := createTables(); err != nil {
		db.Close()
		return err
	}

	return nil
}

func createTables() error {
	queries := []string{

		// ---------------------------------------------------------
		// Users
		// ---------------------------------------------------------

		`
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT NOT NULL UNIQUE,
			email TEXT NOT NULL DEFAULT '',
			password_hash TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'user',
			status TEXT NOT NULL DEFAULT 'active',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
		`,

		// ---------------------------------------------------------
		// Sessions
		// ---------------------------------------------------------

		`
		CREATE TABLE IF NOT EXISTS sessions (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			expires_at TIMESTAMP NOT NULL,

			FOREIGN KEY (user_id)
				REFERENCES users(id)
				ON DELETE CASCADE
		)
		`,

		// ---------------------------------------------------------
		// Secrets
		// ---------------------------------------------------------

		`
		CREATE TABLE IF NOT EXISTS secrets (
			id INTEGER PRIMARY KEY AUTOINCREMENT,

			secret_key TEXT NOT NULL,
			secret_value TEXT NOT NULL,

			created_by TEXT NOT NULL,

			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

			UNIQUE (
				created_by,
				secret_key
			),

			FOREIGN KEY (created_by)
				REFERENCES users(id)
				ON DELETE CASCADE
		)
		`,

		// ---------------------------------------------------------
		// Secret Permissions
		// ---------------------------------------------------------

		`
		CREATE TABLE IF NOT EXISTS secret_permissions (
			secret_id INTEGER NOT NULL,
			user_id TEXT NOT NULL,

			PRIMARY KEY (
				secret_id,
				user_id
			),

			FOREIGN KEY (secret_id)
				REFERENCES secrets(id)
				ON DELETE CASCADE,

			FOREIGN KEY (user_id)
				REFERENCES users(id)
				ON DELETE CASCADE
		)
		`,
	}

	for _, query := range queries {
		if _, err := db.Exec(query); err != nil {
			return fmt.Errorf(
				"failed to create database table: %w",
				err,
			)
		}
	}

	log.Println("[DB] Tables ready")

	return nil
}
