package main

import (
	"fmt"
	"os"
	"path/filepath" 
	"golang.org/x/sys/windows"
	"gopkg.in/yaml.v3"
	"log"
)

func showError(err error) {
	windows.MessageBox(
		0,
		windows.StringToUTF16Ptr(fmt.Sprintf("API-Vault Error:\n\n%v", err)),
		windows.StringToUTF16Ptr("API-Vault"),
		windows.MB_OK|windows.MB_ICONERROR,
	)
}

func loadConfig() error {
	data, err := os.ReadFile("config.yml")

	if os.IsNotExist(err) {
		data = []byte(`app-settings:
  port: 3000
  address: 127.0.0.1

auth:
  admin_username: "Admin"
  admin_password: "Admin"
  
storage:
  appfolder: "appdata"

session:
  duration: 24h
`)

		if err := os.WriteFile("config.yml", data, 0644); err != nil {
			showError(err)
			return err
		}
	} else if err != nil {
		showError(err)
		return err
	}

	if err := yaml.Unmarshal(data, &config); err != nil {
		showError(err)
		return err
	}

	return nil
}

func initStorage() {
	if appfolder == "" {
		appfolder = "appdata"
	}

	if err := os.MkdirAll(appfolder, 0755); err != nil {
		log.Fatal(err)
	}

	usersFile = filepath.Join(appfolder, "users.json")
	permissionsFile = filepath.Join(appfolder, "permissions.json")
	sessions_file = filepath.Join(appfolder, "sessions.json")
	secrets_file = filepath.Join(appfolder, "secrets.json")
}
