package main

import "time"

type Secret struct {
	ID        int64  `json:"id"`
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

type APIUser struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password,omitempty"`
	Role     string `json:"role"`
	Status   string `json:"status"`
}

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
	SecretID int64    `json:"secret_id"`
	UserIDs  []string `json:"user_ids"`
}

type Session struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Config struct {
	AppSettings struct {
		Port    int    `yaml:"port"`
		Address string `yaml:"address"`
	} `yaml:"app-settings"`

	Auth struct {
		AdminUsername string `yaml:"admin_username"`
		AdminPassword string `yaml:"admin_password"`
	} `yaml:"auth"`

	Database struct {
		Host     string `yaml:"host"`
		Port     int    `yaml:"port"`
		Username string `yaml:"username"`
		Password string `yaml:"password"`
		Name     string `yaml:"name"`
	} `yaml:"database"`

	Storage struct {
		AppFolder string `yaml:"appfolder"`
		KeyFile   string `yaml:"key_file"`
	} `yaml:"storage"`

	Session struct {
		Duration      string `yaml:"duration"`
		SecureCookies bool   `yaml:"secure_cookies"`
	} `yaml:"session"`
}

var (
	config        Config
	encryptionKey []byte
)
