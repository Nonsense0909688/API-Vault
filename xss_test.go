package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The keys page interpolates the username into a JavaScript string literal:
//
//	window.currentUsername = "{{.Username}}"
//
// Under text/template that value was written verbatim, so a username could
// close the string and run script for every viewer. html/template escapes it
// for the JS context instead.
func TestUsernameIsEscapedInTemplates(t *testing.T) {
	_, _, adminCookie, _ := newTestVault(t)

	payload := `";alert(document.cookie);//`

	usersMu.Lock()
	users, err := loadJSON[APIUser](usersFile)
	if err != nil {
		usersMu.Unlock()
		t.Fatalf("load users: %v", err)
	}

	for i := range users {
		if users[i].Role == "admin" {
			users[i].Username = payload
		}
	}

	if err := saveJSON(usersFile, users); err != nil {
		usersMu.Unlock()
		t.Fatalf("save users: %v", err)
	}
	usersMu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/keys", nil)
	req.AddCookie(adminCookie)

	rec := httptest.NewRecorder()
	handlekeysPage(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("keys page: %d", rec.Code)
	}

	body := rec.Body.String()

	if strings.Contains(body, `window.currentUsername = "";alert(`) {
		t.Fatalf("username broke out of the JS string literal:\n%s", excerpt(body))
	}

	if !strings.Contains(body, "currentUsername") {
		t.Fatalf("expected the username assignment to still be rendered:\n%s", excerpt(body))
	}
}

func excerpt(body string) string {
	i := strings.Index(body, "currentUsername")
	if i < 0 {
		return "(assignment not found)"
	}

	end := i + 200
	if end > len(body) {
		end = len(body)
	}

	return body[i:end]
}
