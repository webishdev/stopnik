package admin

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/webishdev/stopnik/internal/config"
)

func setupUnauthenticatedHandler(t *testing.T) (string, *Store, http.Handler) {
	t.Helper()
	baseDir, store := setupStore(t)
	handler, handlerError := NewHandler(store, &config.Config{}, "")
	if handlerError != nil {
		t.Fatal(handlerError)
	}
	return baseDir, store, handler
}

func login(t *testing.T, handler http.Handler, username string, password string) *http.Response {
	t.Helper()
	return post(t, handler, "/login", url.Values{"username": {username}, "password": {password}}).Result()
}

func Test_AuthRequiresSignIn(t *testing.T) {
	baseDir, _, handler := setupUnauthenticatedHandler(t)
	writeEntry(t, baseDir, "client.d", "foo", testClientFile("foo"))

	for _, target := range []string{"/", "/clients", "/clients/foo", "/settings/server", "/unknown"} {
		if recorder := get(t, handler, target); recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/login" {
			t.Errorf("GET %s: expected redirect to sign in, got %d %s", target, recorder.Code, recorder.Header().Get("Location"))
		}
	}
	recorder := post(t, handler, "/clients/new", url.Values{"id": {"bar"}, "redirects": {"https://example.com"}})
	if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/login" {
		t.Errorf("expected redirect to sign in, got %d", recorder.Code)
	}
	if recorder := get(t, handler, "/assets/admin.css"); recorder.Code != http.StatusOK {
		t.Errorf("expected assets without sign in, got %d", recorder.Code)
	}

	body := get(t, handler, "/login").Body.String()
	for _, expected := range []string{"No administrator exists yet", "configured manually"} {
		if !strings.Contains(body, expected) {
			t.Errorf("expected sign in page to contain %q", expected)
		}
	}
	// configuration details are not revealed
	for _, unexpected := range []string{"name=\"password\"", "href=\"/clients\"", "/logout", "admin = true", "user.d", baseDir} {
		if strings.Contains(body, unexpected) {
			t.Errorf("expected sign in page without %q", unexpected)
		}
	}

	writeEntry(t, baseDir, "user.d", "admin", testAdminFile("admin"))
	if body := get(t, handler, "/login").Body.String(); !strings.Contains(body, "name=\"password\"") || strings.Contains(body, "No administrator") {
		t.Error("expected sign in form when an administrator exists")
	}
}

func Test_AuthLoginAndLogout(t *testing.T) {
	baseDir, _, handler := setupUnauthenticatedHandler(t)
	writeEntry(t, baseDir, "user.d", "admin", testAdminFile("admin"))
	writeEntry(t, baseDir, "user.d", "user", strings.Replace(testAdminFile("user"), "admin = true", "admin = false", 1))

	for _, credentials := range [][2]string{{"admin", "wrong"}, {"user", testAdminPassword}, {"missing", testAdminPassword}} {
		response := login(t, handler, credentials[0], credentials[1])
		if response.StatusCode != http.StatusUnauthorized || len(response.Cookies()) != 0 {
			t.Errorf("sign in as %s: expected to be rejected, got %d", credentials[0], response.StatusCode)
		}
	}
	if body := post(t, handler, "/login", url.Values{"username": {"admin"}, "password": {"wrong"}}).Body.String(); !strings.Contains(body, "Invalid credentials") {
		t.Error("expected invalid credentials message")
	}

	response := login(t, handler, "admin", testAdminPassword)
	cookies := response.Cookies()
	if response.StatusCode != http.StatusSeeOther || response.Header.Get("Location") != "/" || len(cookies) != 1 {
		t.Fatalf("expected sign in, got %d", response.StatusCode)
	}
	cookie := cookies[0]
	if cookie.Name != sessionCookieName || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" {
		t.Errorf("unexpected session cookie %+v", cookie)
	}
	authenticated := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.AddCookie(cookie)
		handler.ServeHTTP(w, r)
	})

	if body := get(t, authenticated, "/").Body.String(); !strings.Contains(body, "Overview") || !strings.Contains(body, "Signed in as admin") {
		t.Error("expected overview for signed-in administrator")
	}
	if recorder := get(t, authenticated, "/login"); recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/" {
		t.Errorf("expected signed-in administrator to be redirected to overview, got %d", recorder.Code)
	}

	recorder := post(t, authenticated, "/logout", url.Values{})
	if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/login" {
		t.Errorf("expected redirect to sign in, got %d", recorder.Code)
	}
	if removed := recorder.Result().Cookies(); len(removed) != 1 || removed[0].MaxAge >= 0 {
		t.Errorf("expected session cookie to be removed, got %v", removed)
	}
	if recorder := get(t, authenticated, "/"); recorder.Code != http.StatusSeeOther {
		t.Errorf("expected session to end with sign out, got %d", recorder.Code)
	}
}

func Test_AuthBlocksAfterFailedAttempts(t *testing.T) {
	baseDir, _, handler := setupUnauthenticatedHandler(t)
	writeEntry(t, baseDir, "user.d", "admin", testAdminFile("admin"))

	for range 10 {
		login(t, handler, "admin", "wrong")
	}
	if response := login(t, handler, "admin", testAdminPassword); response.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected sign in to be blocked, got %d", response.StatusCode)
	}
}

func Test_AuthOtherAddressNotBlocked(t *testing.T) {
	baseDir, _, handler := setupUnauthenticatedHandler(t)
	writeEntry(t, baseDir, "user.d", "admin", testAdminFile("admin"))

	for range 10 {
		login(t, handler, "admin", "wrong")
	}

	// Failed attempts from one address must not lock out the administrator signing in from another address
	values := url.Values{"username": {"admin"}, "password": {testAdminPassword}}
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.RemoteAddr = "198.51.100.7:51234"
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusSeeOther {
		t.Errorf("expected sign in from another address to succeed, got %d", recorder.Code)
	}
}

func Test_AuthSessionEndsWithoutAdminFlag(t *testing.T) {
	baseDir, _, handler := setupHandler(t)

	if recorder := get(t, handler, "/"); recorder.Code != http.StatusOK {
		t.Fatalf("expected overview, got %d", recorder.Code)
	}
	writeEntry(t, baseDir, "user.d", "admin", testUserFile("admin"))
	if recorder := get(t, handler, "/"); recorder.Code != http.StatusSeeOther {
		t.Errorf("expected session to end without admin flag, got %d", recorder.Code)
	}
	// the session stays ended, even when the flag is added again
	writeEntry(t, baseDir, "user.d", "admin", testAdminFile("admin"))
	if recorder := get(t, handler, "/"); recorder.Code != http.StatusSeeOther {
		t.Errorf("expected session to stay ended, got %d", recorder.Code)
	}
}

func Test_AuthOwnUser(t *testing.T) {
	baseDir, store, handler := setupHandler(t)
	users := mustKind(t, store, "users")
	entry, _, _ := store.Get(users, "admin")

	for _, values := range []url.Values{
		{"hash": {entry.Hash}, "username": {"admin"}},
		{"hash": {entry.Hash}, "username": {"renamed"}, "admin": {"true"}},
	} {
		recorder := post(t, handler, "/users/admin", values)
		if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), ErrOwnAdmin.Error()) {
			t.Errorf("expected own user to stay administrator, got %d", recorder.Code)
		}
	}
	recorder := post(t, handler, "/users/admin/delete", url.Values{"hash": {entry.Hash}})
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), ErrOwnAdmin.Error()) {
		t.Errorf("expected own user not to be deleted, got %d", recorder.Code)
	}

	recorder = post(t, handler, "/users/admin", url.Values{"hash": {entry.Hash}, "username": {"admin"}, "admin": {"true"}, "givenName": {"Ada"}})
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("expected own user to be saved, got %d: %s", recorder.Code, recorder.Body.String())
	}

	// other users can be administrators too
	recorder = post(t, handler, "/users/new", url.Values{"username": {"other"}, "secret": {"bar"}, "admin": {"true"}})
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d: %s", recorder.Code, recorder.Body.String())
	}
	_, content := onlyFile(t, filepath.Join(baseDir, "user.d"))
	user, parseError := config.ParseUser([]byte(content), toml.Unmarshal)
	if parseError != nil {
		t.Fatal(parseError)
	}
	if !user.Admin {
		t.Error("expected new user to be administrator")
	}
	entries, _ := store.List(users)
	for _, other := range entries {
		if other.Key == "other" {
			if body := get(t, handler, "/users/"+other.ID).Body.String(); !strings.Contains(body, "name=\"admin\" value=\"true\" checked") {
				t.Error("expected admin switch to be checked")
			}
			if recorder := post(t, handler, "/users/"+other.ID+"/delete", url.Values{"hash": {other.Hash}}); recorder.Code != http.StatusSeeOther {
				t.Errorf("expected other administrator to be deleted, got %d", recorder.Code)
			}
		}
	}
}
