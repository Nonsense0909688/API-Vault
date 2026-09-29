package main

import (
	"encoding/json"
	"os"
	"time"
)

// Session Cookies storage system

func saveSessions(sessions map[string]time.Time) error {
	data, err := json.MarshalIndent(sessions, "", "    ")
	if err != nil {
		return err
	}

	if err := os.MkdirAll("appdata", 0700); err != nil {
		return err
	}

	return os.WriteFile("appdata/sessions.json", data, 0600)
}

func loadSessions() (map[string]time.Time, error) {
	data, err := os.ReadFile("sessions.json")

	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]time.Time), nil
		}

		return nil, err
	}

	var sessions map[string]time.Time

	if err := json.Unmarshal(data, &sessions); err != nil {
		return nil, err
	}

	if sessions == nil {
		sessions = make(map[string]time.Time)
	}

	return sessions, nil
}

// API Secrets Storage System

func saveSecrets(secrets []Secret) error {
	data, err := json.MarshalIndent(secrets, "", "    ")
	if err != nil {
		return err
	}

	if err := os.MkdirAll("appdata", 0700); err != nil {
		return err
	}

	return os.WriteFile("appdata/secrets.json", data, 0600)
}

func loadSecrets() error {
	data, err := os.ReadFile("secrets.json")

	if err != nil {
		if os.IsNotExist(err) {
			secrets = []Secret{}
			return nil
		}

		return err
	}

	if err := json.Unmarshal(data, &secrets); err != nil {
		return err
	}

	return nil
}
