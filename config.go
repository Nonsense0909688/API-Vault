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

// generatedPasswordNotice is set when loadConfig creates a fresh config, so
// main can print the generated admin password once the logger is up.
var generatedPasswordNotice string

func randomPassword() (string, error) {
	buf := make([]byte, 18)

	if _, err := rand.Read(buf); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// defaultConfig builds the first-run config. The admin password is random
// rather than a fixed "Admin": a secret store that ships with known
// credentials is open to anyone who can reach the port.
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

storage:
  appfolder: "appdata"
  # Path to the AES key. Leave empty to keep it at <appfolder>/encryption.key,
  # which stores it beside the encrypted secrets. Point it somewhere else, or
  # set API_VAULT_ENCRYPTION_KEY, to separate the two.
  key_file: ""

session:
  duration: 24h
  # Marks the session cookie Secure. Turn this on whenever the vault is
  # reachable over HTTPS, including behind a TLS-terminating proxy.
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

		// 0600: this file holds the admin password.
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
		err := fmt.Errorf("auth.admin_password in %s is empty; set a password before starting", configFile)
		showError(err)
		return err
	}

	if config.Auth.AdminPassword == "Admin" {
		log.Printf(
			"[WARN] auth.admin_password is still the old default %q. "+
				"Anyone who can reach this port can log in as admin. Change it in %s.",
			config.Auth.AdminPassword, configFile,
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
		log.Printf("[WARN] %s holds the admin password and is readable beyond its owner (mode %04o); tighten it to 0600.", configFile, mode)
	}
}

func initStorage() {
	folder := config.Storage.AppFolder
	if folder == "" {
		folder = "appdata"
	}

	// Previously this read a package-level var initialised before the config
	// was parsed, so storage.appfolder was silently ignored.
	setAppFolder(folder)

	if err := os.MkdirAll(appfolder, 0700); err != nil {
		log.Fatal(err)
	}
}
