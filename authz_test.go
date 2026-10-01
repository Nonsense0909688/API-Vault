package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newTestVault points the package globals at a temp directory and returns an
// admin and a regular user, each with a live session.
func newTestVault(t *testing.T) (admin, member *APIUser, adminCookie, memberCookie *http.Cookie) {
	t.Helper()

	dir := t.TempDir()
	setAppFolder(dir)

	config = Config{}
	config.Auth.AdminUsername = "Admin"
	config.Auth.AdminPassword = "correct horse battery staple"

	encryptionKey = bytes.Repeat([]byte{0x2a}, 32)

	sessionsMu.Lock()
	sessions = map[string]Session{}
	sessionsMu.Unlock()

	secretsMu.Lock()
	secrets = []Secret{}
	secretsMu.Unlock()

	if err := ensureAdminAccount(); err != nil {
		t.Fatalf("ensureAdminAccount: %v", err)
	}

	users, err := loadJSON[APIUser](usersFile)
	if err != nil {
		t.Fatalf("loadJSON users: %v", err)
	}

	admin = &users[0]

	memberID, err := newID()
	if err != nil {
		t.Fatalf("newID: %v", err)
	}

	memberHash, err := hashPassword("member-password")
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}

	memberUser := APIUser{
		ID:       memberID,
		Username: "member",
		Email:    "member@localhost",
		Password: memberHash,
		Role:     "user",
		Status:   "active",
	}

	users = append(users, memberUser)
	if err := saveJSON(usersFile, users); err != nil {
		t.Fatalf("saveJSON users: %v", err)
	}

	member = &memberUser

	return admin, member, sessionFor(t, admin.ID), sessionFor(t, memberUser.ID)
}

func sessionFor(t *testing.T, userID string) *http.Cookie {
	t.Helper()

	id, err := createSession()
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	if err := storeSession(id, Session{
		UserID:    userID,
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("storeSession: %v", err)
	}

	return &http.Cookie{Name: "session", Value: id}
}

func do(t *testing.T, handler http.HandlerFunc, method, target string, body any, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()

	var reader *bytes.Reader

	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}

	req := httptest.NewRequest(method, target, reader)
	if cookie != nil {
		req.AddCookie(cookie)
	}

	rec := httptest.NewRecorder()
	handler(rec, req)

	return rec
}

// storeSecretAs saves a secret through the real handler, as the given user.
func storeSecretAs(t *testing.T, cookie *http.Cookie, key, value string) {
	t.Helper()

	rec := do(t, handleSaveSecretKey, http.MethodPost, "/api/secrets",
		map[string]string{"key": key, "value": value}, cookie)

	if rec.Code != http.StatusOK {
		t.Fatalf("storing %q: got %d, body %s", key, rec.Code, rec.Body.String())
	}
}

func TestMemberCannotGrantItselfAccessToAnotherUsersSecret(t *testing.T) {
	_, member, adminCookie, memberCookie := newTestVault(t)

	storeSecretAs(t, adminCookie, "stripe-key", "sk_live_secret")

	rec := do(t, handleSaveSecretAccess, http.MethodPost, "/api/secrets/access",
		Permission{Key: "stripe-key", UserIDs: []string{member.ID}}, memberCookie)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when self-granting access, got %d: %s", rec.Code, rec.Body.String())
	}

	// And the secret must still be invisible to them.
	rec = do(t, handleViewSecrets, http.MethodGet, "/api/secrets", nil, memberCookie)

	if strings.Contains(rec.Body.String(), "sk_live_secret") {
		t.Fatalf("member can read another user's secret: %s", rec.Body.String())
	}
}

func TestMemberCannotDeleteAnotherUsersSecret(t *testing.T) {
	_, _, adminCookie, memberCookie := newTestVault(t)

	storeSecretAs(t, adminCookie, "stripe-key", "sk_live_secret")

	rec := do(t, handleDeleteSecret, http.MethodDelete, "/api/secrets",
		map[string]string{"key": "stripe-key"}, memberCookie)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 on foreign delete, got %d: %s", rec.Code, rec.Body.String())
	}

	if _, exists := secretOwner("stripe-key"); !exists {
		t.Fatal("secret was deleted despite the 403")
	}
}

func TestMemberCannotOverwriteAnotherUsersSecret(t *testing.T) {
	_, _, adminCookie, memberCookie := newTestVault(t)

	storeSecretAs(t, adminCookie, "stripe-key", "sk_live_secret")

	rec := do(t, handleSaveSecretKey, http.MethodPost, "/api/secrets",
		map[string]string{"key": "stripe-key", "value": "overwritten"}, memberCookie)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 on foreign overwrite, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestOwnerAndAdminKeepFullControl(t *testing.T) {
	_, member, adminCookie, memberCookie := newTestVault(t)

	// The member owns this one.
	storeSecretAs(t, memberCookie, "member-key", "member-value")

	rec := do(t, handleSaveSecretAccess, http.MethodPost, "/api/secrets/access",
		Permission{Key: "member-key", UserIDs: []string{member.ID}}, memberCookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("owner may share their own secret, got %d: %s", rec.Code, rec.Body.String())
	}

	// An admin may administer anything.
	rec = do(t, handleSaveSecretAccess, http.MethodPost, "/api/secrets/access",
		Permission{Key: "member-key", UserIDs: []string{}}, adminCookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin may share any secret, got %d: %s", rec.Code, rec.Body.String())
	}

	rec = do(t, handleDeleteSecret, http.MethodDelete, "/api/secrets",
		map[string]string{"key": "member-key"}, adminCookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin may delete any secret, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSharedSecretIsVisibleToTheGrantee(t *testing.T) {
	_, member, adminCookie, memberCookie := newTestVault(t)

	storeSecretAs(t, adminCookie, "shared-key", "shared-value")

	rec := do(t, handleSaveSecretAccess, http.MethodPost, "/api/secrets/access",
		Permission{Key: "shared-key", UserIDs: []string{member.ID}}, adminCookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin share failed: %d %s", rec.Code, rec.Body.String())
	}

	rec = do(t, handleViewSecrets, http.MethodGet, "/api/secrets", nil, memberCookie)
	if !strings.Contains(rec.Body.String(), "shared-value") {
		t.Fatalf("grantee cannot read the shared secret: %s", rec.Body.String())
	}
}

func TestMemberCannotCreateUsers(t *testing.T) {
	_, _, _, memberCookie := newTestVault(t)

	rec := do(t, handleCreateUser, http.MethodPost, "/api/users/create",
		map[string]string{"username": "mallory", "password": "pw"}, memberCookie)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestUserListNeverLeaksPasswordHashes(t *testing.T) {
	_, _, adminCookie, memberCookie := newTestVault(t)

	for name, cookie := range map[string]*http.Cookie{"admin": adminCookie, "member": memberCookie} {
		rec := do(t, handleAPIUsers, http.MethodGet, "/api/users", nil, cookie)

		if rec.Code != http.StatusOK {
			t.Fatalf("%s: got %d", name, rec.Code)
		}

		var users []map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &users); err != nil {
			t.Fatalf("%s: decode: %v", name, err)
		}

		if len(users) == 0 {
			t.Fatalf("%s: no users returned", name)
		}

		for _, u := range users {
			if _, present := u["password"]; present {
				t.Fatalf("%s: /api/users exposed a password hash: %v", name, u)
			}
		}
	}
}

func TestDeactivatedUserLosesAccessImmediately(t *testing.T) {
	_, member, adminCookie, memberCookie := newTestVault(t)

	rec := do(t, handleUserStatus, http.MethodPost, "/api/users/status",
		map[string]string{"id": member.ID, "status": "inactive"}, adminCookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("deactivate failed: %d %s", rec.Code, rec.Body.String())
	}

	rec = do(t, handleViewSecrets, http.MethodGet, "/api/secrets", nil, memberCookie)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("deactivated account still works: %d", rec.Code)
	}
}

func TestLastAdminCannotBeRemoved(t *testing.T) {
	admin, _, adminCookie, _ := newTestVault(t)

	rec := do(t, handleDeleteUser, http.MethodPost, "/api/users/delete",
		map[string]string{"id": admin.ID}, adminCookie)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 when deleting the last admin, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestLegacySHA256HashStillLogsInAndIsUpgraded(t *testing.T) {
	newTestVault(t)

	usersMu.Lock()
	users, err := loadJSON[APIUser](usersFile)
	if err != nil {
		usersMu.Unlock()
		t.Fatalf("load users: %v", err)
	}

	// Simulate an install written by the old SHA-256 code.
	legacyID, err := newID()
	if err != nil {
		usersMu.Unlock()
		t.Fatalf("newID: %v", err)
	}

	users = append(users, APIUser{
		ID:       legacyID,
		Username: "legacy",
		Password: legacySHA256("old-password"),
		Role:     "user",
		Status:   "active",
	})

	if err := saveJSON(usersFile, users); err != nil {
		usersMu.Unlock()
		t.Fatalf("save users: %v", err)
	}
	usersMu.Unlock()

	rec := do(t, handleLoginPost, http.MethodPost, "/login/post",
		map[string]string{"username": "legacy", "password": "old-password"}, nil)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("legacy login failed: %d %s", rec.Code, rec.Body.String())
	}

	stored, err := loadJSON[APIUser](usersFile)
	if err != nil {
		t.Fatalf("reload users: %v", err)
	}

	for _, u := range stored {
		if u.Username != "legacy" {
			continue
		}

		if isLegacyHash(u.Password) {
			t.Fatal("hash was not upgraded to bcrypt after login")
		}

		ok, _ := verifyPassword(u.Password, "old-password")
		if !ok {
			t.Fatal("upgraded hash does not verify the original password")
		}

		return
	}

	t.Fatal("legacy user vanished")
}

func TestWrongPasswordIsRejected(t *testing.T) {
	newTestVault(t)

	rec := do(t, handleLoginPost, http.MethodPost, "/login/post",
		map[string]string{"username": "Admin", "password": "wrong"}, nil)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestLoginThrottlesAfterRepeatedFailures(t *testing.T) {
	newTestVault(t)

	attemptsMu.Lock()
	attempts = map[string]*attemptRecord{}
	attemptsMu.Unlock()

	var last int

	for i := 0; i < maxFailedAttempts+1; i++ {
		rec := do(t, handleLoginPost, http.MethodPost, "/login/post",
			map[string]string{"username": "Admin", "password": "wrong"}, nil)
		last = rec.Code
	}

	if last != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after %d failures, got %d", maxFailedAttempts+1, last)
	}
}

func TestSecretsRoundTripThroughEncryption(t *testing.T) {
	_, _, adminCookie, _ := newTestVault(t)

	storeSecretAs(t, adminCookie, "round-trip", "plaintext-value")

	// On disk it must not be readable.
	secretsMu.RLock()
	stored := secrets[0].Value
	secretsMu.RUnlock()

	if strings.Contains(stored, "plaintext-value") {
		t.Fatalf("secret stored unencrypted: %s", stored)
	}

	rec := do(t, handleViewSecrets, http.MethodGet, "/api/secrets", nil, adminCookie)
	if !strings.Contains(rec.Body.String(), "plaintext-value") {
		t.Fatalf("secret did not decrypt: %s", rec.Body.String())
	}
}
