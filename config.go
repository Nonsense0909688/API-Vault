package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"os"

	"gopkg.in/yaml.v3"
)

const configFile = "config.yml"

// generatedPasswordNotice is set when loadConfig creates a fresh config.
var generatedPasswordNotice string

func randomPassword() (string, error) {
	buf := make([]byte, 18)

	if _, err := rand.Read(buf); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func defaultConfig() (string, string, error) {
	password, err := randomPassword()
	if err != nil {
		return "", "", err
	}

	return fmt.Sprintf(`app-settings:
  port: 3000
  address: 127.0.0.1

auth:
  admin_username: "Admin"
  # Generated on first run. Change it after your first login.
  admin_password: %q

database:
  host: 127.0.0.1
  port: 3306
  username: apivault
  password: "CHANGE_ME"
  name: apivault

storage:
  appfolder: "appdata"
  # Path to the AES encryption key.
  # Leave empty to use <appfolder>/encryption.key
  key_file: ""

session:
  duration: 24h
  # Enable when the vault is served over HTTPS.
  secure_cookies: false
`, password), password, nil
}

func loadConfig() error {
	data, err := os.ReadFile(configFile)

	if os.IsNotExist(err) {
		contents, password, genErr := defaultConfig()
		if genErr != nil {
			showError(genErr)
			return genErr
		}

		// 0600 because this file contains the admin password
		// and database credentials.
		if err := os.WriteFile(configFile, []byte(contents), 0600); err != nil {
			showError(err)
			return err
		}

		data = []byte(contents)
		generatedPasswordNotice = password
	} else if err != nil {
		showError(err)
		return err
	} else {
		warnConfigPermissions()
	}

	if err := yaml.Unmarshal(data, &config); err != nil {
		showError(err)
		return err
	}

	return validateConfig()
}

func validateConfig() error {
	if config.Auth.AdminUsername == "" {
		config.Auth.AdminUsername = "Admin"
	}

	if config.AppSettings.Port == 0 {
		config.AppSettings.Port = 3000
	}

	if config.AppSettings.Address == "" {
		config.AppSettings.Address = "127.0.0.1"
	}

	if config.Auth.AdminPassword == "" {
		err := fmt.Errorf(
			"auth.admin_password in %s is empty; set a password before starting",
			configFile,
		)
		showError(err)
		return err
	}

	if config.Database.Host == "" {
		config.Database.Host = "127.0.0.1"
	}

	if config.Database.Port == 0 {
		config.Database.Port = 3306
	}

	if config.Database.Username == "" {
		return fmt.Errorf("database.username in %s is empty", configFile)
	}

	if config.Database.Name == "" {
		return fmt.Errorf("database.name in %s is empty", configFile)
	}

	if config.Auth.AdminPassword == "Admin" {
		log.Printf(
			"[WARN] auth.admin_password is still the old default %q. "+
				"Anyone who can reach this port can log in as admin. Change it in %s.",
			config.Auth.AdminPassword,
			configFile,
		)
	}

	return nil
}

func warnConfigPermissions() {
	info, err := os.Stat(configFile)
	if err != nil {
		return
	}

	if mode := info.Mode().Perm(); mode&0077 != 0 {
		log.Printf(
			"[WARN] %s contains credentials and is readable beyond its owner "+
				"(mode %04o); tighten it to 0600.",
			configFile,
			mode,
		)
	}
}
