package main

import ("time" 
		"path/filepath" 
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

var sessions map[string]Session
var secrets = []Secret{}

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
	} `yaml:"storage"`

	Session struct {
		Duration string `yaml:"duration"`
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

type Permission struct {
	Key     string   `json:"key"`
	UserIDs []string `json:"user_ids"`
}

var appfolder = config.Storage.AppFolder

var (
	usersFile       = filepath.Join(appfolder, "users.json")
	permissionsFile = filepath.Join(appfolder, "permissions.json")
	sessions_file   = filepath.Join(appfolder, "sessions.json")
	secrets_file    = filepath.Join(appfolder, "secrets.json")
)


type Session struct {
	UserID    string    `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`
}


