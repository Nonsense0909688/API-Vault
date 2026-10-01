package main

import (
	"path/filepath"
	"sync"
	"time"
)

type Secret struct {
	Key       string `json:"key"`
	Value     string `json:"value"`
	CreatedBy string `json:"created_by"`
}

type ViewingKey struct {
	Key string `json:"key"`
}

type QueryKey struct {
	Key string `json:"key"`
}

// Shared mutable state. Every handler runs on its own goroutine, so each of
// these needs its lock held for the whole read-modify-write, not just the
// individual map or slice access.
var (
	sessionsMu sync.RWMutex
	sessions   = map[string]Session{}

	secretsMu sync.RWMutex
	secrets   = []Secret{}

	// users.json and permissions.json are re-read on every request, so the
	// lock has to span load+save to keep two concurrent writers from
	// clobbering each other.
	usersMu       sync.Mutex
	permissionsMu sync.Mutex
)

var encryptionKey []byte

type Config struct {
	AppSettings struct {
		Port    int    `yaml:"port"`
		Address string `yaml:"address"`
	} `yaml:"app-settings"`

	Auth struct {
		AdminUsername string `yaml:"admin_username"`
		AdminPassword string `yaml:"admin_password"`
	} `yaml:"auth"`

	Storage struct {
		AppFolder string `yaml:"appfolder"`

		// KeyFile moves the AES key off the data directory. When empty the
		// key is kept at <appfolder>/encryption.key, which means it sits
		// beside the ciphertext it protects.
		KeyFile string `yaml:"key_file"`
	} `yaml:"storage"`

	Session struct {
		Duration string `yaml:"duration"`

		// SecureCookies marks the session cookie Secure, which browsers only
		// send back over HTTPS. Leave it off for plain-HTTP local use; turn it
		// on whenever the vault is reachable over TLS or sits behind a proxy
		// that terminates it.
		SecureCookies bool `yaml:"secure_cookies"`
	} `yaml:"session"`
}

var config Config

type APIUser struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password,omitempty"`
	Role     string `json:"role"`
	Status   string `json:"status"`
}

// Public returns a copy without the password hash, for anything that leaves
// the process. APIUser itself keeps the field because it is what gets
// persisted to users.json.
func (u APIUser) Public() APIUser {
	u.Password = ""
	return u
}

func publicUsers(users []APIUser) []APIUser {
	out := make([]APIUser, 0, len(users))
	for _, u := range users {
		out = append(out, u.Public())
	}
	return out
}

type Permission struct {
	Key     string   `json:"key"`
	UserIDs []string `json:"user_ids"`
}

// Set by initStorage once the config has actually been read. They cannot be
// initialised here: package-level vars run before loadConfig, so anything
// derived from config at this point is always the zero value.
var (
	appfolder       string
	usersFile       string
	permissionsFile string
	sessions_file   string
	secrets_file    string
)

type Session struct {
	UserID    string    `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

func init() {
	setAppFolder("appdata")
}

func setAppFolder(folder string) {
	appfolder = folder
	usersFile = filepath.Join(appfolder, "users.json")
	permissionsFile = filepath.Join(appfolder, "permissions.json")
	sessions_file = filepath.Join(appfolder, "sessions.json")
	secrets_file = filepath.Join(appfolder, "secrets.json")
}
