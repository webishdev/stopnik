package config

import (
	"crypto/sha256"
	"os"
	"sync"
	"time"

	"github.com/webishdev/stopnik/log"
)

// ConfigReader function definition to read and validate a Config by file name.
type ConfigReader func(name string) (*Config, error)

// Watcher polls a configuration file and provides a new Config when the file content changed and is valid.
// Invalid changes are reported as warning and ignored, so the previously loaded Config stays active.
type Watcher struct {
	name     string
	read     ConfigReader
	onValid  func(*Config)
	done     chan struct{}
	stopOnce sync.Once
	seenHash [sha256.Size]byte
	lastStat fileStat
	pending  *fileStat
	missing  bool
}

type fileStat struct {
	modTime time.Time
	size    int64
}

func (stat fileStat) equal(other fileStat) bool {
	return stat.size == other.size && stat.modTime.Equal(other.modTime)
}

// NewWatcher creates and starts a Watcher for the given file name, checking for changes in the given interval.
// The current file content is treated as already loaded.
func NewWatcher(name string, interval time.Duration, read ConfigReader, onValid func(*Config)) *Watcher {
	watcher := &Watcher{
		name:    name,
		read:    read,
		onValid: onValid,
		done:    make(chan struct{}),
	}

	if stat, statError := os.Stat(name); statError == nil {
		watcher.lastStat = fileStat{modTime: stat.ModTime(), size: stat.Size()}
	}
	if data, readError := os.ReadFile(name); readError == nil {
		watcher.seenHash = sha256.Sum256(data)
	}

	go watcher.run(interval)

	return watcher
}

// Close stops the Watcher.
func (watcher *Watcher) Close() {
	watcher.stopOnce.Do(func() {
		close(watcher.done)
	})
}

func (watcher *Watcher) run(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-watcher.done:
			return
		case <-ticker.C:
			watcher.check()
		}
	}
}

// check detects changes by file stat, a change must be stable for two consecutive checks
// to avoid reading files which are still written.
func (watcher *Watcher) check() {
	stat, statError := os.Stat(watcher.name)
	if statError != nil {
		if !watcher.missing {
			log.Warn("Configuration file %s not accessible, keeping previous configuration: %v", watcher.name, statError)
			watcher.missing = true
		}
		watcher.pending = nil
		return
	}
	watcher.missing = false

	current := fileStat{modTime: stat.ModTime(), size: stat.Size()}
	if current.equal(watcher.lastStat) {
		watcher.pending = nil
		return
	}

	if watcher.pending == nil || !watcher.pending.equal(current) {
		watcher.pending = &current
		return
	}

	watcher.pending = nil

	data, readError := os.ReadFile(watcher.name)
	if readError != nil {
		log.Warn("Configuration file %s could not be read, keeping previous configuration: %v", watcher.name, readError)
		return
	}
	watcher.lastStat = current

	hash := sha256.Sum256(data)
	if hash == watcher.seenHash {
		return
	}
	watcher.seenHash = hash

	config, configError := watcher.read(watcher.name)
	if configError != nil {
		log.Warn("Configuration file %s changed but is invalid, keeping previous configuration: %v", watcher.name, configError)
		return
	}

	log.Info("Configuration file %s changed, restarting STOPnik", watcher.name)
	watcher.onValid(config)
}
