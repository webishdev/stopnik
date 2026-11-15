package admin

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/crypto"
)

func setupHandler(t *testing.T) (string, *Store, http.Handler) {
	t.Helper()
	baseDir, store := setupStore(t)
	staticConfig := &config.Config{
		Server: config.Server{Addr: ":8082", Secret: "very-secret-value"},
		UI:     config.UI{Title: "Test realm"},
	}
	handler, handlerError := NewHandler(store, staticConfig, "", false)
	if handlerError != nil {
		t.Fatal(handlerError)
	}
	return baseDir, store, signIn(t, baseDir, handler, "")
}

const testAdminPassword = "admin-secret"

var testAdminHash = sync.OnceValue(func() string {
	hashed, _ := crypto.BcryptHash(testAdminPassword)
	return hashed
})

func testAdminFile(username string) string {
	return "username = \"" + username + "\"\npassword = \"" + testAdminHash() + "\"\nadmin = true\n"
}

// signIn creates the administrator admin and returns a handler which sends its session cookie with every request.
func signIn(t *testing.T, baseDir string, handler http.Handler, basePath string) http.Handler {
	t.Helper()
	writeEntry(t, baseDir, "user.d", "admin", testAdminFile("admin"))
	recorder := post(t, handler, basePath+"/login", url.Values{"username": {"admin"}, "password": {testAdminPassword}})
	cookies := recorder.Result().Cookies()
	if recorder.Code != http.StatusSeeOther || len(cookies) != 1 {
		t.Fatalf("expected sign in, got %d: %s", recorder.Code, recorder.Body.String())
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.AddCookie(cookies[0])
		handler.ServeHTTP(w, r)
	})
}

func get(t *testing.T, handler http.Handler, target string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, target, nil))
	return recorder
}

func post(t *testing.T, handler http.Handler, target string, values url.Values) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, target, strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

// onlyFile returns the name and content of the only file inside the given directory, the signed-in administrator is ignored.
func onlyFile(t *testing.T, dir string) (string, string) {
	t.Helper()
	dirEntries, readError := os.ReadDir(dir)
	if readError != nil {
		t.Fatal(readError)
	}
	dirEntries = slices.DeleteFunc(dirEntries, func(dirEntry os.DirEntry) bool {
		return dirEntry.Name() == "admin.toml"
	})
	if len(dirEntries) != 1 {
		t.Fatalf("expected exactly one file in %s, got %v", dir, dirEntries)
	}
	data, fileError := os.ReadFile(filepath.Join(dir, dirEntries[0].Name()))
	if fileError != nil {
		t.Fatal(fileError)
	}
	return dirEntries[0].Name(), string(data)
}

func Test_HandlerShowsLegacyHashes(t *testing.T) {
	baseDir, _, handler := setupHandler(t)
	legacyHash := "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181"
	writeEntry(t, baseDir, "client.d", "legacy", "id = \"legacy\"\nclientSecret = \""+legacyHash+"\"\nredirects = [\"https://example.com/callback\"]\n")
	writeEntry(t, baseDir, "user.d", "legacy", "username = \"legacy\"\npassword = \""+legacyHash+"\"\n")

	if body := get(t, handler, "/clients").Body.String(); !strings.Contains(body, "Legacy SHA512 secret hash") {
		t.Error("expected legacy client secret hash to be shown")
	}
	if body := get(t, handler, "/users").Body.String(); !strings.Contains(body, "Legacy SHA512 password hash") {
		t.Error("expected legacy password hash to be shown")
	}
}

func Test_HandlerPages(t *testing.T) {
	baseDir, _, handler := setupHandler(t)
	writeEntry(t, baseDir, "client.d", "foo", testClientFile("foo"))
	writeEntry(t, baseDir, "client.d", "broken", "id = ")
	writeEntry(t, baseDir, "user.d", "bar", testUserFile("bar"))
	writeEntry(t, baseDir, "classification.d", "baz", "user = \"bar\"\nclient = \"foo\"\n\n[[claims]]\nname = \"role\"\nvalue = \"admin\"\n")

	testData := []struct {
		target   string
		status   int
		contains string
	}{
		{"/", http.StatusOK, "Overview"},
		{"/clients", http.StatusOK, "href=\"/clients/foo\""},
		{"/users", http.StatusOK, "bar"},
		{"/users", http.StatusOK, "class=\"admin-check\""},
		{"/classifications", http.StatusOK, "role"},
		{"/clients/new", http.StatusOK, "name=\"redirects\""},
		{"/users/new", http.StatusOK, "name=\"username\""},
		{"/classifications/new", http.StatusOK, "name=\"claim.0.name\""},
		{"/clients/foo", http.StatusOK, "value=\"foo\""},
		{"/clients/broken", http.StatusOK, "can not be edited"},
		{"/clients/foo/delete", http.StatusOK, "Delete client"},
		{"/clients", http.StatusOK, "commandfor=\"delete-foo\" command=\"show-modal\""},
		{"/clients", http.StatusOK, "<dialog id=\"delete-foo\""},
		{"/clients/foo", http.StatusOK, "<dialog id=\"delete-foo\""},
		{"/users/bar", http.StatusOK, "value=\"bar\""},
		{"/classifications/baz", http.StatusOK, "value=\"role\""},
		{"/clients/missing", http.StatusNotFound, "Nothing here"},
		{"/clients/..%2Ffoo", http.StatusNotFound, ""},
		{"/unknown", http.StatusNotFound, ""},
		{"/assets/admin.css", http.StatusOK, ":root"},
		{"/assets/logo.png", http.StatusOK, ""},
		{"/assets/other", http.StatusNotFound, ""},
	}
	for _, test := range testData {
		recorder := get(t, handler, test.target)
		if recorder.Code != test.status {
			t.Errorf("GET %s: expected status %d, got %d", test.target, test.status, recorder.Code)
		}
		body := recorder.Body.String()
		if !strings.Contains(body, test.contains) {
			t.Errorf("GET %s: expected body to contain %q", test.target, test.contains)
		}
		if strings.HasPrefix(recorder.Header().Get("Content-Type"), "text/html") && strings.Contains(strings.ToLower(body), "toml") {
			t.Errorf("GET %s: body must not mention toml", test.target)
		}
	}
}

func Test_HandlerOverviewStaticConfig(t *testing.T) {
	_, store, handler := setupHandler(t)

	body := get(t, handler, "/").Body.String()
	for _, expected := range []string{"Static configuration", "Listening on :8082", "Test realm", "href=\"/settings/server\"", "href=\"/settings/forward-auth\"", "/assets/admin.css?v=" + cssVersion} {
		if !strings.Contains(body, expected) {
			t.Errorf("expected overview to contain %q", expected)
		}
	}
	for _, unexpected := range []string{"stopnik:introspect", "very-secret-value"} {
		if strings.Contains(body, unexpected) {
			t.Errorf("expected overview to only show a summary, found %q", unexpected)
		}
	}

	withoutConfig, handlerError := NewHandler(store, nil, "", false)
	if handlerError != nil {
		t.Fatal(handlerError)
	}
	withoutConfig = signIn(t, filepath.Dir(mustKind(t, store, "users").Dir), withoutConfig, "")
	if body := get(t, withoutConfig, "/").Body.String(); strings.Contains(body, "Static configuration") {
		t.Error("expected no static configuration without config")
	}
	if recorder := get(t, withoutConfig, "/settings/server"); recorder.Code != http.StatusNotFound {
		t.Errorf("expected no settings pages without config, got %d", recorder.Code)
	}
}

func Test_HandlerBreadcrumb(t *testing.T) {
	_, _, handler := setupHandler(t)

	if body := get(t, handler, "/clients").Body.String(); !strings.Contains(body, `<span class="breadcrumb">Dynamic configuration</span>`) {
		t.Error("expected list page breadcrumb to be the dynamic configuration")
	}
	if body := get(t, handler, "/clients/new").Body.String(); !strings.Contains(body, `<a class="breadcrumb" href="/clients">Clients</a>`) {
		t.Error("expected edit page breadcrumb to link to the list")
	}
}

func Test_HandlerSettingsPages(t *testing.T) {
	baseDir, _, handler := setupHandler(t)

	testData := []struct {
		target   string
		status   int
		contains string
	}{
		{"/settings/server", http.StatusOK, "value=\":8082\" readonly"},
		{"/settings/server", http.StatusOK, "placeholder=\"stopnik:introspect\""},
		{"/settings/server", http.StatusOK, "placeholder=\"Configured, hidden\""},
		{"/settings/cookies", http.StatusOK, "placeholder=\"stopnik_auth\""},
		{"/settings/cookies", http.StatusOK, "disabled checked"},
		{"/settings/tls", http.StatusOK, "placeholder=\"Disabled\""},
		{"/settings/forward-auth", http.StatusOK, "placeholder=\"/forward\""},
		{"/settings/ui", http.StatusOK, "value=\"Test realm\""},
		{"/settings/dynamic", http.StatusOK, "value=\"" + filepath.Join(baseDir, "client.d") + "\""},
		{"/settings/unknown", http.StatusNotFound, ""},
		{"/settings/new", http.StatusNotFound, ""},
	}
	for _, test := range testData {
		recorder := get(t, handler, test.target)
		if recorder.Code != test.status {
			t.Errorf("GET %s: expected status %d, got %d", test.target, test.status, recorder.Code)
		}
		body := recorder.Body.String()
		if !strings.Contains(body, test.contains) {
			t.Errorf("GET %s: expected body to contain %q", test.target, test.contains)
		}
		if strings.Contains(body, "very-secret-value") {
			t.Errorf("GET %s: body must not show the server secret", test.target)
		}
		// the only form is the sign-out form in the navigation
		if strings.Count(body, "<form") != 1 {
			t.Errorf("GET %s: static configuration must be read-only", test.target)
		}
		if strings.Contains(strings.ToLower(body), "toml") {
			t.Errorf("GET %s: body must not mention toml", test.target)
		}
	}

	recorder := get(t, handler, "/settings")
	if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/settings/server" {
		t.Errorf("expected redirect to the first topic, got %d %s", recorder.Code, recorder.Header().Get("Location"))
	}
}

func Test_HandlerCreateAndEditClient(t *testing.T) {
	baseDir, store, handler := setupHandler(t)

	recorder := post(t, handler, "/clients/new", url.Values{
		"id":               {"my client"},
		"secret":           {"s3cret"},
		"redirects":        {"https://example.com/a\r\n\r\nhttps://example.com/b"},
		"oidc":             {"true"},
		"grantTypes":       {"authorization_code", "refresh_token"},
		"accessTTL":        {"10"},
		"pkceOptional":     {"true"},
		"pkcePlainAllowed": {"true"},
	})
	if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/clients?done=saved&name=my+client" {
		t.Fatalf("expected redirect, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if message := get(t, handler, recorder.Header().Get("Location")).Body.String(); !strings.Contains(message, "Client &#39;my client&#39; saved") {
		t.Error("expected saved message")
	}

	fileName, content := onlyFile(t, filepath.Join(baseDir, "client.d"))
	id := strings.TrimSuffix(fileName, ".toml")
	client, parseError := config.ParseClient([]byte(content), toml.Unmarshal, nil, true)
	if parseError != nil {
		t.Fatal(parseError)
	}
	if client.Id != "my client" || !client.Oidc || client.AccessTTL != 10 || len(client.Redirects) != 2 || len(client.GrantTypes) != 2 {
		t.Errorf("unexpected client %+v", client)
	}
	if client.GetRequirePkce() || !client.PkcePlainAllowed {
		t.Errorf("expected PKCE to be optional and plain to be allowed, got %+v", client)
	}
	if !crypto.VerifySecret("s3cret", client.Salt, client.ClientSecret) {
		t.Error("expected secret to be hashed")
	}

	// edit without a new secret keeps the existing hash
	entry, _, _ := store.Get(mustKind(t, store, "clients"), id)
	recorder = post(t, handler, "/clients/"+id, url.Values{
		"hash":      {entry.Hash},
		"id":        {"my client"},
		"redirects": {"https://example.com/c"},
	})
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d: %s", recorder.Code, recorder.Body.String())
	}
	_, content = onlyFile(t, filepath.Join(baseDir, "client.d"))
	edited, _ := config.ParseClient([]byte(content), toml.Unmarshal, nil, true)
	if edited.ClientSecret != client.ClientSecret || edited.Oidc || len(edited.Redirects) != 1 || edited.AccessTTL != 0 {
		t.Errorf("unexpected client %+v", edited)
	}
	if !edited.GetRequirePkce() || edited.PkcePlainAllowed || strings.Contains(content, "requirePkce") {
		t.Errorf("expected PKCE to be required by default again, got %s", content)
	}

	// a stale hash is rejected
	recorder = post(t, handler, "/clients/"+id, url.Values{
		"hash":      {entry.Hash},
		"id":        {"my client"},
		"redirects": {"https://example.com/d"},
	})
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "changed in the meantime") {
		t.Errorf("expected conflict, got %d", recorder.Code)
	}
}

func Test_HandlerCreateInvalidUser(t *testing.T) {
	baseDir, _, handler := setupHandler(t)

	recorder := post(t, handler, "/users/new", url.Values{"username": {"foo"}})
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "missing password") {
		t.Errorf("expected validation error, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if dirEntries, _ := os.ReadDir(filepath.Join(baseDir, "user.d")); len(dirEntries) != 1 {
		t.Errorf("expected nothing to be written, got %v", dirEntries)
	}

	recorder = post(t, handler, "/users/new", url.Values{"username": {"foo"}, "secret": {"bar"}, "givenName": {"John"}, "city": {"Town"}})
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d: %s", recorder.Code, recorder.Body.String())
	}
	_, content := onlyFile(t, filepath.Join(baseDir, "user.d"))
	user, parseError := config.ParseUser([]byte(content), toml.Unmarshal, true)
	if parseError != nil {
		t.Fatal(parseError)
	}
	if user.UserProfile.GivenName != "John" || user.UserInformation.Address == nil || user.UserInformation.Address.City != "Town" {
		t.Errorf("unexpected user %+v", user)
	}

	recorder = post(t, handler, "/users/new", url.Values{"username": {"foo"}, "secret": {"bar"}})
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "already exists") {
		t.Errorf("expected duplicate error, got %d", recorder.Code)
	}
}

func Test_HandlerEditKeepsUnknownSettings(t *testing.T) {
	baseDir, store, handler := setupHandler(t)
	content := testUserFile("foo") + "\n[roles]\nclient = [\"admin\"]\n\n[userProfile]\ngivenName = \"John\"\n\n[userInformation]\nemail = \"john@example.com\"\nphoneVerified = true\n"
	writeEntry(t, baseDir, "user.d", "foo", content)

	entry, _, _ := store.Get(mustKind(t, store, "users"), "foo")
	recorder := post(t, handler, "/users/foo", url.Values{"hash": {entry.Hash}, "username": {"foo"}, "familyName": {"Doe"}})
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d: %s", recorder.Code, recorder.Body.String())
	}

	var result struct {
		Username        string
		Password        string
		Roles           map[string][]string `toml:"roles"`
		UserProfile     map[string]string   `toml:"userProfile"`
		UserInformation map[string]any      `toml:"userInformation"`
	}
	_, saved := onlyFile(t, filepath.Join(baseDir, "user.d"))
	if _, decodeError := toml.Decode(saved, &result); decodeError != nil {
		t.Fatal(decodeError)
	}
	if result.Password != testPassword || len(result.Roles["client"]) != 1 {
		t.Errorf("expected password and roles to be kept: %s", saved)
	}
	if result.UserProfile["givenName"] != "" || result.UserProfile["familyName"] != "Doe" {
		t.Errorf("expected profile to be replaced by the form: %s", saved)
	}
	if _, hasEmail := result.UserInformation["email"]; hasEmail || result.UserInformation["phoneVerified"] != true {
		t.Errorf("expected email removed and unknown phoneVerified kept: %s", saved)
	}
}

func Test_HandlerClassification(t *testing.T) {
	baseDir, _, handler := setupHandler(t)

	recorder := post(t, handler, "/classifications/new", url.Values{"action": {"addClaim"}, "claims": {"0"}})
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "claim.1.name") {
		t.Errorf("expected form with two claim rows, got %d", recorder.Code)
	}

	recorder = post(t, handler, "/classifications/new", url.Values{
		"users":          {"foo"},
		"clients":        {"a\nb"},
		"claims":         {"2"},
		"claim.0.name":   {"role"},
		"claim.0.values": {"admin\nuser"},
		"claim.0.scopes": {"roles"},
		"claim.1.name":   {""},
	})
	if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/classifications?done=saved" {
		t.Fatalf("expected redirect, got %d: %s", recorder.Code, recorder.Body.String())
	}
	_, content := onlyFile(t, filepath.Join(baseDir, "classification.d"))
	classification, parseError := config.ParseClassification([]byte(content), toml.Unmarshal)
	if parseError != nil {
		t.Fatal(parseError)
	}
	if classification.User != "foo" || len(classification.Clients) != 2 || len(classification.Claims) != 1 || classification.Claims[0].Scope != "roles" {
		t.Errorf("unexpected classification %s", content)
	}
}

func Test_HandlerDelete(t *testing.T) {
	baseDir, store, handler := setupHandler(t)
	writeEntry(t, baseDir, "client.d", "foo", testClientFile("foo"))
	writeEntry(t, baseDir, "client.d", "broken", "id = ")
	clients := mustKind(t, store, "clients")

	recorder := post(t, handler, "/clients/foo/delete", url.Values{"hash": {"stale"}})
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "changed in the meantime") {
		t.Errorf("expected conflict, got %d", recorder.Code)
	}

	for _, id := range []string{"foo", "broken"} {
		entry, _, _ := store.Get(clients, id)
		recorder = post(t, handler, "/clients/"+id+"/delete", url.Values{"hash": {entry.Hash}})
		if recorder.Code != http.StatusSeeOther {
			t.Fatalf("expected redirect, got %d", recorder.Code)
		}
	}
	if dirEntries, _ := os.ReadDir(filepath.Join(baseDir, "client.d")); len(dirEntries) != 0 {
		t.Errorf("expected all entries to be deleted, got %v", dirEntries)
	}
}

func Test_HandlerRejectsCrossOriginPost(t *testing.T) {
	baseDir, _, handler := setupHandler(t)

	request := httptest.NewRequest(http.MethodPost, "/clients/new", strings.NewReader(url.Values{"id": {"foo"}, "redirects": {"https://example.com"}}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Sec-Fetch-Site", "cross-site")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Errorf("expected forbidden, got %d", recorder.Code)
	}
	if dirEntries, _ := os.ReadDir(filepath.Join(baseDir, "client.d")); len(dirEntries) != 0 {
		t.Error("expected no file to be written")
	}
}

func Test_HandlerBasePath(t *testing.T) {
	baseDir, store := setupStore(t)
	handler, handlerError := NewHandler(store, &config.Config{}, "admin/", false)
	if handlerError != nil {
		t.Fatal(handlerError)
	}
	handler = signIn(t, baseDir, handler, "/admin")
	writeEntry(t, baseDir, "client.d", "foo", testClientFile("foo"))

	tests := []struct {
		target   string
		status   int
		contains string
	}{
		{"/admin/", http.StatusOK, "href=\"/admin/clients\""},
		{"/admin/", http.StatusOK, "/admin/assets/admin.css?v=" + cssVersion},
		{"/admin/clients", http.StatusOK, "href=\"/admin/clients/foo\""},
		{"/admin/clients/foo", http.StatusOK, "action=\"/admin/clients/foo/delete\""},
		{"/admin/assets/admin.css", http.StatusOK, ":root"},
		{"/", http.StatusNotFound, "href=\"/admin/\""},
		{"/clients", http.StatusNotFound, ""},
		{"/administrator/", http.StatusNotFound, ""},
	}
	for _, test := range tests {
		recorder := get(t, handler, test.target)
		if recorder.Code != test.status {
			t.Errorf("GET %s: expected status %d, got %d", test.target, test.status, recorder.Code)
		}
		if body := recorder.Body.String(); !strings.Contains(body, test.contains) {
			t.Errorf("GET %s: expected body to contain %q", test.target, test.contains)
		}
	}

	redirects := map[string]string{
		"/admin":          "/admin/",
		"/admin/settings": "/admin/settings/server",
	}
	for target, location := range redirects {
		if recorder := get(t, handler, target); recorder.Header().Get("Location") != location {
			t.Errorf("GET %s: expected redirect to %s, got %d %s", target, location, recorder.Code, recorder.Header().Get("Location"))
		}
	}

	recorder := post(t, handler, "/admin/users/new", url.Values{"username": {"foo"}, "secret": {"bar"}})
	if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/admin/users?done=saved&name=foo" {
		t.Errorf("expected redirect below base path, got %d %s", recorder.Code, recorder.Header().Get("Location"))
	}
}
