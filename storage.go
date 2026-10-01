package main

import (
	"encoding/json"
	"os"
)

func loadSessions() (map[string]Session, error) {
	data, err := os.ReadFile(sessions_file)
	if os.IsNotExist(err) {
		return map[string]Session{}, nil
	}
	if err != nil {
		return nil, err
	}

	var sessions map[string]Session
	err = json.Unmarshal(data, &sessions)
	if sessions == nil {
		sessions = map[string]Session{}
	}
	return sessions, err
}

func saveSessions(s map[string]Session) error {
	if err := ensureData(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(sessions_file, b, 0600)
}

func loadSecrets() error {
	data, err := os.ReadFile(secrets_file)
	if os.IsNotExist(err) {
		secrets = []Secret{}
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &secrets)
}

func saveSecrets(s []Secret) error {
	return saveJSON(secrets_file, s)
}

func loadJSON[T any](file string) ([]T, error) {
	if err := ensureData(); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(file)
	if os.IsNotExist(err) || len(data) == 0 {
		return []T{}, nil
	}
	if err != nil {
		return nil, err
	}

	var result []T
	return result, json.Unmarshal(data, &result)
}

func saveJSON[T any](file string, data []T) error {
	if err := ensureData(); err != nil {
		return err
	}

	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(file, b, 0600)
}
