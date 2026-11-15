package admin

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"uuid"
)

const testPassword = "$2a$10$jvXVHUYe.kb5njbxI2QUOOY/TDDi880X0jC01h1CrhUNagGN.KcDq"

func testClientFile(id string) string {
	return "# comment\nid = \"" + id + "\"\nredirects = [\"https://example.com/callback\"]\n"
}

func testUserFile(username string) string {
	return "username = \"" + username + "\"\npassword = \"" + testPassword + "\"\n"
}

// setupStore creates a Store with dynamic directories inside a temporary directory, the user directory does not exist.
func setupStore(t *testing.T) (string, *Store) {
	t.Helper()
	baseDir := t.TempDir()
	for _, dir := range []string{"client.d", "classification.d"} {
		if mkdirError := os.Mkdir(filepath.Join(baseDir, dir), 0700); mkdirError != nil {
			t.Fatal(mkdirError)
		}
	}
	store := NewStore(filepath.Join(baseDir, "client.d"), filepath.Join(baseDir, "user.d"), filepath.Join(baseDir, "classification.d"), nil)
	return baseDir, store
}

func mustKind(t *testing.T, store *Store, name string) *Kind {
	t.Helper()
	kind, exists := store.Kind(name)
	if !exists {
		t.Fatalf("kind %s not found", name)
	}
	return kind
}

func writeEntry(t *testing.T, baseDir string, dir string, id string, content string) {
	t.Helper()
	if mkdirError := os.MkdirAll(filepath.Join(baseDir, dir), 0700); mkdirError != nil {
		t.Fatal(mkdirError)
	}
	if writeError := os.WriteFile(filepath.Join(baseDir, dir, id+".toml"), []byte(content), 0600); writeError != nil {
		t.Fatal(writeError)
	}
}

func Test_StoreCreateListUpdateDelete(t *testing.T) {
	baseDir, store := setupStore(t)
	clients := mustKind(t, store, "clients")

	id, createError := store.Create(clients, []byte(testClientFile("foo")))
	if createError != nil {
		t.Fatal(createError)
	}
	if _, parseError := uuid.Parse(id); parseError != nil {
		t.Errorf("expected uuid as id, got %s", id)
	}
	if _, statError := os.Stat(filepath.Join(baseDir, "client.d", id+".toml")); statError != nil {
		t.Error(statError)
	}
	writeEntry(t, baseDir, "client.d", "invalid", "id = \"invalid\"")
	writeEntry(t, baseDir, "client.d", "bar", testClientFile("bar"))

	entries, listError := store.List(clients)
	if listError != nil {
		t.Fatal(listError)
	}
	if len(entries) != 3 || entries[0].Label != "bar" || entries[1].Label != "foo" || entries[2].ID != "invalid" {
		t.Fatalf("unexpected entries %v", entries)
	}
	if !entries[1].Valid() || entries[1].ID != id || entries[1].Client == nil {
		t.Errorf("expected valid entry foo, got %v", entries[1])
	}
	if entries[2].Valid() || !strings.Contains(entries[2].Error, "missing redirects") {
		t.Errorf("expected invalid entry, got %v", entries[2])
	}

	entry, content, getError := store.Get(clients, id)
	if getError != nil || string(content) != testClientFile("foo") || entry.Key != "foo" {
		t.Fatalf("unexpected entry %v, %s, %v", entry, content, getError)
	}

	updated := testClientFile("foo") + "oidc = true\n"
	if updateError := store.Update(clients, id, []byte(updated), "wrong"); !errors.Is(updateError, ErrConflict) {
		t.Errorf("expected ErrConflict, got %v", updateError)
	}
	if updateError := store.Update(clients, id, []byte(testClientFile("bar")), entry.Hash); updateError == nil || !strings.Contains(updateError.Error(), "already exists") {
		t.Errorf("expected duplicate error, got %v", updateError)
	}
	if updateError := store.Update(clients, id, []byte(updated), entry.Hash); updateError != nil {
		t.Fatal(updateError)
	}
	entry, content, _ = store.Get(clients, id)
	if string(content) != updated || !entry.Client.Oidc {
		t.Errorf("unexpected content %s", content)
	}

	if deleteError := store.Delete(clients, id, entry.Hash); deleteError != nil {
		t.Fatal(deleteError)
	}
	if _, _, getError = store.Get(clients, id); !errors.Is(getError, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", getError)
	}

	dirEntries, _ := os.ReadDir(filepath.Join(baseDir, "client.d"))
	if len(dirEntries) != 2 {
		t.Errorf("unexpected files left %v", dirEntries)
	}
}

func Test_StoreFindUserAndHasAdmin(t *testing.T) {
	baseDir, store := setupStore(t)
	if store.HasAdmin() || store.FindUser("foo") != nil {
		t.Error("expected no users without directory")
	}

	writeEntry(t, baseDir, "user.d", "foo", testUserFile("foo"))
	writeEntry(t, baseDir, "user.d", "broken", "username = \"bar\"\nadmin = true\n")
	if store.HasAdmin() {
		t.Error("expected invalid users not to count as administrator")
	}
	if user := store.FindUser("foo"); user == nil || user.Admin {
		t.Errorf("expected user foo without admin flag, got %+v", user)
	}
	if store.FindUser("bar") != nil {
		t.Error("expected invalid user not to be found")
	}

	writeEntry(t, baseDir, "user.d", "foo", testUserFile("foo")+"admin = true\n")
	if !store.HasAdmin() || !store.FindUser("foo").Admin {
		t.Error("expected user foo to be administrator")
	}
}

func Test_StoreRejectsInvalidData(t *testing.T) {
	_, store := setupStore(t)
	clients := mustKind(t, store, "clients")
	users := mustKind(t, store, "users")

	if _, createError := store.Create(clients, []byte("id = ")); createError == nil {
		t.Error("expected parse error")
	}
	if _, createError := store.Create(users, []byte("username = \"foo\"\npassword = \"plain\"\n")); createError == nil {
		t.Error("expected validation error for plain password")
	}
	if _, createError := store.Create(users, []byte(testUserFile("foo"))); createError != nil {
		t.Fatal(createError)
	}
	_, createError := store.Create(users, []byte(testUserFile("foo")))
	if createError == nil || createError.Error() != "user with username 'foo' already exists" {
		t.Errorf("expected duplicate error, got %v", createError)
	}
}

func Test_StoreRejectsInvalidIds(t *testing.T) {
	_, store := setupStore(t)
	clients := mustKind(t, store, "clients")

	for _, id := range []string{"../foo", ".foo", "a/b", "..", ""} {
		if _, _, getError := store.Get(clients, id); !errors.Is(getError, ErrInvalidID) {
			t.Errorf("expected ErrInvalidID for %q, got %v", id, getError)
		}
		if updateError := store.Update(clients, id, []byte(testClientFile("foo")), ""); !errors.Is(updateError, ErrInvalidID) {
			t.Errorf("expected ErrInvalidID for %q, got %v", id, updateError)
		}
		if deleteError := store.Delete(clients, id, ""); !errors.Is(deleteError, ErrInvalidID) {
			t.Errorf("expected ErrInvalidID for %q, got %v", id, deleteError)
		}
	}
}

func Test_StoreMissingDirectory(t *testing.T) {
	baseDir, store := setupStore(t)
	users := mustKind(t, store, "users")

	entries, listError := store.List(users)
	if listError != nil || len(entries) != 0 {
		t.Fatalf("expected empty list, got %v, %v", entries, listError)
	}
	id, createError := store.Create(users, []byte(testUserFile("foo")))
	if createError != nil {
		t.Fatal(createError)
	}
	if _, statError := os.Stat(filepath.Join(baseDir, "user.d", id+".toml")); statError != nil {
		t.Error(statError)
	}
}
