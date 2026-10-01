package main

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// ensureData creates the directory the data files actually live in. It used
// to create a hardcoded "data" folder, which is not where anything is written
// once storage.appfolder is configured.
func ensureData() error {
	return os.MkdirAll(appfolder, 0700)
}

// writeFileAtomic avoids leaving a half-written vault behind if the process
// dies mid-save: write a sibling temp file, fsync, then rename over the target.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	if err := ensureData(); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}

	tmpName := tmp.Name()

	defer func() {
		tmp.Close()
		os.Remove(tmpName)
	}()

	if err := tmp.Chmod(perm); err != nil {
		return err
	}

	if _, err := tmp.Write(data); err != nil {
		return err
	}

	if err := tmp.Sync(); err != nil {
		return err
	}

	if err := tmp.Close(); err != nil {
		return err
	}

	return os.Rename(tmpName, path)
}

func loadSessions() (map[string]Session, error) {
	data, err := os.ReadFile(sessions_file)
	if os.IsNotExist(err) {
		return map[string]Session{}, nil
	}
	if err != nil {
		return nil, err
	}

	var loaded map[string]Session
	err = json.Unmarshal(data, &loaded)
	if loaded == nil {
		loaded = map[string]Session{}
	}
	return loaded, err
}

// saveSessionsLocked persists the session map. Callers must already hold
// sessionsMu.
func saveSessionsLocked() error {
	b, err := json.MarshalIndent(sessions, "", "  ")
	if err != nil {
		return err
	}

	return writeFileAtomic(sessions_file, b, 0600)
}

func loadSecrets() error {
	secretsMu.Lock()
	defer secretsMu.Unlock()

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

// saveSecretsLocked persists the secret list. Callers must already hold
// secretsMu.
func saveSecretsLocked() error {
	b, err := json.MarshalIndent(secrets, "", "  ")
	if err != nil {
		return err
	}

	return writeFileAtomic(secrets_file, b, 0600)
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
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	return writeFileAtomic(file, b, 0600)
}
