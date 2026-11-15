package admin

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"uuid"

	"github.com/BurntSushi/toml"
	"github.com/webishdev/stopnik/internal/config"
)

var (
	ErrNotFound  = errors.New("entry not found")
	ErrConflict  = errors.New("the entry was changed in the meantime, reload and try again")
	ErrInvalidID = errors.New("invalid entry id")
)

// idPattern restricts ids to names which can be used as file name inside the directory of a kind.
var idPattern = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9._-]*$`)

const fileSuffix = ".toml"

// Kind describes one type of dynamic configuration entries and the directory they are stored in.
type Kind struct {
	Name     string
	Title    string
	Singular string
	KeyName  string
	Dir      string
	parse    func(entry *Entry, data []byte) error
}

// Entry describes a single entry of the dynamic configuration.
// The ID identifies the entry inside the admin web user interface, it is the file name without suffix.
// Depending on the kind, one of Client, User or Classification is set when the entry is valid.
type Entry struct {
	ID             string
	Key            string
	Label          string
	Error          string
	Hash           string
	Client         *config.Client
	User           *config.User
	Classification *config.Classification
}

// Valid returns whether the entry is valid.
func (entry *Entry) Valid() bool {
	return entry.Error == ""
}

// Store reads and writes the dynamic configuration files of clients, users and classifications.
// Every write is validated with the same rules STOPnik uses when loading the files.
type Store struct {
	kinds []*Kind
	mutex sync.Mutex
}

// NewStore creates a Store for the given directories, the optional ClientCheck is used to validate clients.
func NewStore(clientsDir string, usersDir string, classificationsDir string, clientCheck config.ClientCheck) *Store {
	return &Store{
		kinds: []*Kind{
			{
				Name:     "clients",
				Title:    "Clients",
				Singular: "Client",
				KeyName:  "id",
				Dir:      clientsDir,
				parse: func(entry *Entry, data []byte) error {
					client, parseError := config.ParseClient(data, toml.Unmarshal, clientCheck)
					if parseError != nil {
						return parseError
					}
					entry.Client, entry.Key, entry.Label = client, client.Id, client.Id
					return nil
				},
			},
			{
				Name:     "users",
				Title:    "Users",
				Singular: "User",
				KeyName:  "username",
				Dir:      usersDir,
				parse: func(entry *Entry, data []byte) error {
					user, parseError := config.ParseUser(data, toml.Unmarshal)
					if parseError != nil {
						return parseError
					}
					entry.User, entry.Key, entry.Label = user, user.Username, user.Username
					return nil
				},
			},
			{
				Name:     "classifications",
				Title:    "Classifications",
				Singular: "Classification",
				Dir:      classificationsDir,
				parse: func(entry *Entry, data []byte) error {
					classification, parseError := config.ParseClassification(data, toml.Unmarshal)
					if parseError != nil {
						return parseError
					}
					entry.Classification, entry.Label = classification, classificationLabel(classification)
					return nil
				},
			},
		},
	}
}

// Kinds returns all known kinds.
func (store *Store) Kinds() []*Kind {
	return store.kinds
}

// Kind returns the kind with the given name.
func (store *Store) Kind(name string) (*Kind, bool) {
	for _, kind := range store.kinds {
		if kind.Name == name {
			return kind, true
		}
	}
	return nil, false
}

// List returns all entries of the given kind sorted by label, a missing directory results in an empty list.
func (store *Store) List(kind *Kind) ([]*Entry, error) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	return store.list(kind)
}

func (store *Store) list(kind *Kind) ([]*Entry, error) {
	dirEntries, readError := os.ReadDir(kind.Dir)
	if errors.Is(readError, fs.ErrNotExist) {
		return nil, nil
	} else if readError != nil {
		return nil, readError
	}

	var entries []*Entry
	for _, dirEntry := range dirEntries {
		id, isEntry := strings.CutSuffix(dirEntry.Name(), fileSuffix)
		if dirEntry.IsDir() || !isEntry || !idPattern.MatchString(id) {
			continue
		}
		entry := &Entry{ID: id}
		data, fileError := os.ReadFile(filepath.Join(kind.Dir, dirEntry.Name()))
		if fileError != nil {
			entry.Error = fileError.Error()
		} else {
			entry.Hash = hash(data)
			if parseError := parseEntry(kind, entry, data); parseError != nil {
				entry.Error = parseError.Error()
			}
		}
		entries = append(entries, entry)
	}
	slices.SortFunc(entries, func(a, b *Entry) int {
		return cmpEntries(a, b)
	})
	return entries, nil
}

// cmpEntries sorts valid entries by label, invalid entries last.
func cmpEntries(a, b *Entry) int {
	if a.Valid() != b.Valid() {
		if a.Valid() {
			return -1
		}
		return 1
	}
	if result := strings.Compare(strings.ToLower(a.Label), strings.ToLower(b.Label)); result != 0 {
		return result
	}
	return strings.Compare(a.ID, b.ID)
}

// FindUser returns the valid user with the given username, or nil when there is none.
func (store *Store) FindUser(username string) *config.User {
	for _, entry := range store.validUsers() {
		if entry.Key == username {
			return entry.User
		}
	}
	return nil
}

// HasAdmin returns whether at least one valid user is allowed to sign in to the admin web user interface.
func (store *Store) HasAdmin() bool {
	return slices.ContainsFunc(store.validUsers(), func(entry *Entry) bool {
		return entry.User.Admin
	})
}

// validUsers returns all valid user entries, unreadable directories result in no users.
func (store *Store) validUsers() []*Entry {
	kind, _ := store.Kind("users")
	entries, _ := store.List(kind)
	return slices.DeleteFunc(entries, func(entry *Entry) bool {
		return !entry.Valid()
	})
}

// Get returns the entry with the given id and its content.
func (store *Store) Get(kind *Kind, id string) (*Entry, []byte, error) {
	name, nameError := filePath(kind, id)
	if nameError != nil {
		return nil, nil, nameError
	}
	data, readError := os.ReadFile(name)
	if errors.Is(readError, fs.ErrNotExist) {
		return nil, nil, ErrNotFound
	} else if readError != nil {
		return nil, nil, readError
	}
	entry := &Entry{ID: id, Hash: hash(data)}
	if parseError := parseEntry(kind, entry, data); parseError != nil {
		entry.Error = parseError.Error()
	}
	return entry, data, nil
}

// Create validates the data and stores it as new entry with a generated id, returns the id.
func (store *Store) Create(kind *Kind, data []byte) (string, error) {
	store.mutex.Lock()
	defer store.mutex.Unlock()

	id := uuid.New().String()
	name, nameError := filePath(kind, id)
	if nameError != nil {
		return "", nameError
	}
	if validationError := store.validate(kind, id, data); validationError != nil {
		return "", validationError
	}
	if dirError := os.MkdirAll(kind.Dir, 0o755); dirError != nil {
		return "", dirError
	}
	return id, writeFile(name, data, 0o644)
}

// Update validates the data and replaces an existing entry.
// The expectedHash must match the current content, otherwise ErrConflict is returned.
func (store *Store) Update(kind *Kind, id string, data []byte, expectedHash string) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()

	name, stat, checkError := checkExisting(kind, id, expectedHash)
	if checkError != nil {
		return checkError
	}
	if validationError := store.validate(kind, id, data); validationError != nil {
		return validationError
	}
	return writeFile(name, data, stat.Mode().Perm())
}

// Delete removes an existing entry, the expectedHash must match the current content, otherwise ErrConflict is returned.
func (store *Store) Delete(kind *Kind, id string, expectedHash string) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()

	name, _, checkError := checkExisting(kind, id, expectedHash)
	if checkError != nil {
		return checkError
	}
	return os.Remove(name)
}

// validate parses the data and checks that its key is not used by another entry of the same kind.
func (store *Store) validate(kind *Kind, id string, data []byte) error {
	entry := &Entry{}
	if parseError := parseEntry(kind, entry, data); parseError != nil {
		return parseError
	}
	if entry.Key == "" {
		return nil
	}
	entries, listError := store.list(kind)
	if listError != nil {
		return listError
	}
	for _, other := range entries {
		if other.ID != id && other.Key == entry.Key {
			return fmt.Errorf("%s with %s '%s' already exists", strings.ToLower(kind.Singular), kind.KeyName, entry.Key)
		}
	}
	return nil
}

// checkExisting returns the path and file info of an existing entry whose content matches the expectedHash.
func checkExisting(kind *Kind, id string, expectedHash string) (string, os.FileInfo, error) {
	name, nameError := filePath(kind, id)
	if nameError != nil {
		return "", nil, nameError
	}
	stat, statError := os.Stat(name)
	if errors.Is(statError, fs.ErrNotExist) {
		return "", nil, ErrNotFound
	} else if statError != nil {
		return "", nil, statError
	}
	data, readError := os.ReadFile(name)
	if readError != nil {
		return "", nil, readError
	}
	if hash(data) != expectedHash {
		return "", nil, ErrConflict
	}
	return name, stat, nil
}

// writeFile writes into a temporary file first and renames it afterward,
// so STOPnik never reads a partially written file. The temporary file has no .toml suffix and is ignored by STOPnik.
func writeFile(name string, data []byte, perm os.FileMode) error {
	tmp, createError := os.CreateTemp(filepath.Dir(name), "."+filepath.Base(name)+".*.tmp")
	if createError != nil {
		return createError
	}
	tmpName := tmp.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()

	if _, writeError := tmp.Write(data); writeError != nil {
		_ = tmp.Close()
		return writeError
	}
	if closeError := tmp.Close(); closeError != nil {
		return closeError
	}
	if chmodError := os.Chmod(tmpName, perm); chmodError != nil {
		return chmodError
	}
	return os.Rename(tmpName, name)
}

// filePath returns the path of the file for the given id inside the directory of the kind, when the id is valid.
func filePath(kind *Kind, id string) (string, error) {
	if !idPattern.MatchString(id) {
		return "", ErrInvalidID
	}
	return filepath.Join(kind.Dir, id+fileSuffix), nil
}

// parseEntry parses the data into the entry, errors are described without referring to the file format.
func parseEntry(kind *Kind, entry *Entry, data []byte) error {
	return friendlyError(kind.parse(entry, data))
}

// friendlyError removes the technical prefix of errors caused by decoding the data.
func friendlyError(err error) error {
	if err == nil {
		return nil
	}
	var parseError toml.ParseError
	if errors.As(err, &parseError) {
		return fmt.Errorf("invalid settings in line %d: %s", parseError.Position.Line, parseError.Message)
	}
	return errors.New(strings.TrimPrefix(err.Error(), "toml: "))
}

func hash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// classificationLabel describes to whom a classification applies.
// Users and clients must match, an empty list never matches, an empty list of scopes matches all scopes.
func classificationLabel(classification *config.Classification) string {
	return fmt.Sprintf("%s · %s", joinOr(merge(classification.User, classification.Users), "no users"),
		joinOr(merge(classification.Client, classification.Clients), "no clients"))
}

func joinOr(values []string, empty string) string {
	if len(values) == 0 {
		return empty
	}
	return strings.Join(values, ", ")
}
