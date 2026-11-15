package config

import (
	"cmp"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/webishdev/stopnik/internal/oauth2"
	"github.com/webishdev/stopnik/log"
)

// Entries defines the dynamic part of the configuration, consisting of clients, users and classifications.
type Entries struct {
	Clients         []Client
	Users           []User
	Classifications []Classification
}

// dynamicSnapshot is an immutable view of the currently active dynamic configuration.
type dynamicSnapshot struct {
	version         uint64
	clients         []*Client
	clientMap       map[string]*Client
	userMap         map[string]*User
	classifications []Classification
	oidc            bool
}

var emptySnapshot = &dynamicSnapshot{
	clientMap: map[string]*Client{},
	userMap:   map[string]*User{},
}

// newDynamicSnapshot creates a snapshot from the given entries.
// Duplicate client ids or usernames are skipped, the first entry wins, an error for each duplicate is returned.
func newDynamicSnapshot(clients []*Client, users []*User, classifications []*Classification) (*dynamicSnapshot, []error) {
	var duplicates []error
	snapshot := &dynamicSnapshot{
		clientMap: make(map[string]*Client),
		userMap:   make(map[string]*User),
	}

	for _, client := range clients {
		if _, exists := snapshot.clientMap[client.Id]; exists {
			duplicates = append(duplicates, fmt.Errorf("client with id '%s' is defined more then once", client.Id))
			continue
		}
		snapshot.clientMap[client.Id] = client
		snapshot.clients = append(snapshot.clients, client)
		snapshot.oidc = snapshot.oidc || client.Oidc
		warnDeprecatedGrantTypes(client)
	}

	for _, user := range users {
		if _, exists := snapshot.userMap[user.Username]; exists {
			duplicates = append(duplicates, fmt.Errorf("user with username '%s' is defined more then once", user.Username))
			continue
		}
		snapshot.userMap[user.Username] = user
	}

	for _, classification := range classifications {
		current := *classification
		prepareClassification(&current)
		snapshot.classifications = append(snapshot.classifications, current)
	}

	return snapshot, duplicates
}

// warnDeprecatedGrantTypes logs a warning when the given Client is allowed to use deprecated grant types.
// https://datatracker.ietf.org/doc/html/rfc9700#section-2.1.2
// https://datatracker.ietf.org/doc/html/rfc9700#section-2.4
func warnDeprecatedGrantTypes(client *Client) {
	for _, deprecatedGrantType := range []oauth2.GrantType{oauth2.GtPassword, oauth2.GtImplicit} {
		grantTypeConfigured := slices.ContainsFunc(client.GrantTypes, func(configuredGrantType string) bool {
			return strings.EqualFold(configuredGrantType, string(deprecatedGrantType))
		})
		if grantTypeConfigured {
			log.Warn("Client %s uses the grant type %s, which is deprecated and removed in OAuth 2.1", client.Id, deprecatedGrantType)
		}
	}
}

// getDynamic returns the currently active dynamic configuration, never nil.
func (config *Config) getDynamic() *dynamicSnapshot {
	if config.dynamic == nil {
		return emptySnapshot
	}
	snapshot := config.dynamic.Load()
	if snapshot == nil {
		return emptySnapshot
	}
	return snapshot
}

// setDynamic makes the given snapshot the active dynamic configuration.
func (config *Config) setDynamic(snapshot *dynamicSnapshot) {
	snapshot.version = config.getDynamic().version + 1
	config.dynamic.Store(snapshot)
}

// ApplyEntries makes the given Entries the active dynamic configuration, without further validation.
// Returns an error when client ids or usernames are not unique.
func (config *Config) ApplyEntries(entries Entries) error {
	if config.dynamic == nil {
		return fmt.Errorf("config not initialized")
	}
	snapshot, duplicates := newDynamicSnapshot(pointers(entries.Clients), pointers(entries.Users), pointers(entries.Classifications))
	if len(duplicates) > 0 {
		return duplicates[0]
	}
	config.setDynamic(snapshot)
	return nil
}

// GetClients returns all currently loaded clients, without the ForwardAuth client.
func (config *Config) GetClients() []*Client {
	return config.getDynamic().clients
}

// GetDynamicVersion returns a number which changes whenever the dynamic configuration changes.
func (config *Config) GetDynamicVersion() uint64 {
	return config.getDynamic().version
}

// GetDynamicInterval returns the interval in which the dynamic configuration is checked for changes.
// When no interval is provided a default value will be returned.
func (config *Config) GetDynamicInterval() time.Duration {
	return time.Duration(cmp.Or(config.Dynamic.Interval, 2)) * time.Second
}

// GetClientsDir returns the directory which contains client configuration files.
func (config *Config) GetClientsDir() string {
	return filepath.Join(config.configDir, "client.d")
}

// GetUsersDir returns the directory which contains user configuration files.
func (config *Config) GetUsersDir() string {
	return filepath.Join(config.configDir, "user.d")
}

// GetClassificationsDir returns the directory which contains classification configuration files.
func (config *Config) GetClassificationsDir() string {
	return filepath.Join(config.configDir, "classification.d")
}

func pointers[T any](values []T) []*T {
	result := make([]*T, len(values))
	for index := range values {
		result[index] = &values[index]
	}
	return result
}

// ClientCheck function definition for additional checks of a Client, e.g. whether its private key can be loaded.
type ClientCheck func(client *Client) error

type entryKind string

const (
	kindClient         entryKind = "client"
	kindUser           entryKind = "user"
	kindClassification entryKind = "classification"
)

type dynamicFile struct {
	kind           entryKind
	stat           fileStat
	hash           [sha256.Size]byte
	client         *Client
	user           *User
	classification *Classification
}

func (file *dynamicFile) hasEntry() bool {
	return file.client != nil || file.user != nil || file.classification != nil
}

// DynamicStore loads clients, users and classifications from directories, one entry per TOML file.
// Each file is loaded and validated on its own, invalid files are skipped and reported as warning.
// When a previously valid file becomes invalid, its last valid entry stays active.
type DynamicStore struct {
	config      *Config
	unmarshaler Unmarshal
	clientCheck ClientCheck
	mutex       sync.Mutex
	files       map[string]*dynamicFile
	pending     map[string]fileStat
	missingDirs map[string]bool
}

// NewDynamicStore creates a DynamicStore which applies the loaded entries to the given Config.
// The optional ClientCheck is called for each Client after validation.
func NewDynamicStore(config *Config, unmarshaler Unmarshal, clientCheck ClientCheck) *DynamicStore {
	return &DynamicStore{
		config:      config,
		unmarshaler: unmarshaler,
		clientCheck: clientCheck,
		files:       make(map[string]*dynamicFile),
		pending:     make(map[string]fileStat),
		missingDirs: make(map[string]bool),
	}
}

// Load reads all files from the dynamic configuration directories and applies them.
func (dynamicStore *DynamicStore) Load() {
	dynamicStore.scan(false)
}

// Poll checks the dynamic configuration directories for changes and applies them.
// A changed file must be stable for two consecutive polls to avoid reading files which are still written.
func (dynamicStore *DynamicStore) Poll() {
	dynamicStore.scan(true)
}

func (dynamicStore *DynamicStore) scan(requireStable bool) {
	dynamicStore.mutex.Lock()
	defer dynamicStore.mutex.Unlock()

	directories := []struct {
		kind entryKind
		dir  string
	}{
		{kindClient, dynamicStore.config.GetClientsDir()},
		{kindUser, dynamicStore.config.GetUsersDir()},
		{kindClassification, dynamicStore.config.GetClassificationsDir()},
	}

	changed := false
	seen := make(map[string]bool)
	for _, directory := range directories {
		for _, name := range dynamicStore.listFiles(directory.dir) {
			seen[name] = true
			changed = dynamicStore.check(directory.kind, name, requireStable) || changed
		}
	}

	for name, file := range dynamicStore.files {
		if !seen[name] {
			log.Info("Dynamic configuration file %s removed", name)
			delete(dynamicStore.files, name)
			changed = changed || file.hasEntry()
		}
	}
	for name := range dynamicStore.pending {
		if !seen[name] {
			delete(dynamicStore.pending, name)
		}
	}

	if changed || dynamicStore.config.getDynamic() == emptySnapshot {
		dynamicStore.apply()
	}
}

// listFiles returns the sorted names of all TOML files inside the given directory.
func (dynamicStore *DynamicStore) listFiles(dir string) []string {
	dirEntries, readError := os.ReadDir(dir)
	if readError != nil {
		if !dynamicStore.missingDirs[dir] {
			if errors.Is(readError, fs.ErrNotExist) {
				log.Info("Dynamic configuration directory %s does not exist", dir)
			} else {
				log.Warn("Dynamic configuration directory %s not accessible: %v", dir, readError)
			}
			dynamicStore.missingDirs[dir] = true
		}
		return nil
	}
	delete(dynamicStore.missingDirs, dir)

	var names []string
	for _, dirEntry := range dirEntries {
		if dirEntry.IsDir() || !strings.HasSuffix(dirEntry.Name(), ".toml") {
			continue
		}
		names = append(names, filepath.Join(dir, dirEntry.Name()))
	}
	slices.Sort(names)
	return names
}

// check loads the given file when it is new or changed, returns whether the active entries changed.
func (dynamicStore *DynamicStore) check(kind entryKind, name string, requireStable bool) bool {
	stat, statError := os.Stat(name)
	if statError != nil {
		return false
	}
	current := fileStat{modTime: stat.ModTime(), size: stat.Size()}

	existing := dynamicStore.files[name]
	if existing != nil && existing.stat.equal(current) {
		delete(dynamicStore.pending, name)
		return false
	}

	if requireStable {
		pending, isPending := dynamicStore.pending[name]
		if !isPending || !pending.equal(current) {
			dynamicStore.pending[name] = current
			return false
		}
	}
	delete(dynamicStore.pending, name)

	data, readError := os.ReadFile(name)
	if readError != nil {
		log.Warn("Dynamic configuration file %s could not be read: %v", name, readError)
		return false
	}

	hash := sha256.Sum256(data)
	if existing != nil && existing.hash == hash {
		existing.stat = current
		return false
	}

	file := &dynamicFile{kind: kind, stat: current, hash: hash}
	if parseError := dynamicStore.parse(file, data); parseError != nil {
		if existing != nil && existing.hasEntry() {
			log.Warn("Dynamic configuration file %s is invalid, keeping previous %s: %v", name, kind, parseError)
			existing.stat = current
			existing.hash = hash
		} else {
			log.Warn("Dynamic configuration file %s is invalid, skipped: %v", name, parseError)
			dynamicStore.files[name] = file
		}
		return false
	}

	log.Info("Dynamic configuration file %s loaded", name)
	dynamicStore.files[name] = file
	return true
}

// parse decodes and validates a single entry of the given kind.
func (dynamicStore *DynamicStore) parse(file *dynamicFile, data []byte) error {
	var parseError error
	switch file.kind {
	case kindClient:
		file.client, parseError = ParseClient(data, dynamicStore.unmarshaler, dynamicStore.clientCheck)
	case kindUser:
		file.user, parseError = ParseUser(data, dynamicStore.unmarshaler)
	case kindClassification:
		file.classification, parseError = ParseClassification(data, dynamicStore.unmarshaler)
	}
	return parseError
}

// ParseClient decodes and validates a single Client from a dynamic configuration file.
// The optional ClientCheck is called after validation.
func ParseClient(data []byte, unmarshaler Unmarshal, clientCheck ClientCheck) (*Client, error) {
	client := &Client{}
	if parseError := unmarshaler(data, client); parseError != nil {
		return nil, parseError
	}
	if validationError := ValidateClient(client); validationError != nil {
		return nil, validationError
	}
	if clientCheck != nil {
		if checkError := clientCheck(client); checkError != nil {
			return nil, checkError
		}
	}
	return client, nil
}

// ParseUser decodes and validates a single User from a dynamic configuration file.
func ParseUser(data []byte, unmarshaler Unmarshal) (*User, error) {
	user := &User{}
	if parseError := unmarshaler(data, user); parseError != nil {
		return nil, parseError
	}
	if validationError := ValidateUser(user); validationError != nil {
		return nil, validationError
	}
	return user, nil
}

// ParseClassification decodes and validates a single Classification from a dynamic configuration file.
func ParseClassification(data []byte, unmarshaler Unmarshal) (*Classification, error) {
	classification := &Classification{}
	if parseError := unmarshaler(data, classification); parseError != nil {
		return nil, parseError
	}
	if validationError := ValidateClassification(classification); validationError != nil {
		return nil, validationError
	}
	return classification, nil
}

// apply builds a new snapshot from all valid files in name order and makes it active.
func (dynamicStore *DynamicStore) apply() {
	names := make([]string, 0, len(dynamicStore.files))
	for name := range dynamicStore.files {
		names = append(names, name)
	}
	slices.Sort(names)

	var clients []*Client
	var users []*User
	var classifications []*Classification
	for _, name := range names {
		file := dynamicStore.files[name]
		switch {
		case file.client != nil:
			clients = append(clients, file.client)
		case file.user != nil:
			users = append(users, file.user)
		case file.classification != nil:
			classifications = append(classifications, file.classification)
		}
	}

	snapshot, duplicates := newDynamicSnapshot(clients, users, classifications)
	for _, duplicate := range duplicates {
		log.Warn("Dynamic configuration skipped: %v", duplicate)
	}

	dynamicStore.config.setDynamic(snapshot)
	log.Info("Dynamic configuration applied with %d clients, %d users and %d classifications", len(snapshot.clientMap), len(snapshot.userMap), len(snapshot.classifications))
	if len(snapshot.clientMap) == 0 {
		log.Warn("No clients configured, add at least one client to %s", dynamicStore.config.GetClientsDir())
	}
	if len(snapshot.userMap) == 0 {
		log.Warn("No users configured, add at least one user to %s", dynamicStore.config.GetUsersDir())
	}
}
