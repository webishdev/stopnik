package config

import (
	"sync"
	"time"
)

// Watcher polls the directories of a DynamicStore and applies valid changes.
// Invalid changes are reported as warning and ignored, so the previously loaded entries stay active.
type Watcher struct {
	dynamicStore *DynamicStore
	done         chan struct{}
	stopOnce     sync.Once
}

type fileStat struct {
	modTime time.Time
	size    int64
}

func (stat fileStat) equal(other fileStat) bool {
	return stat.size == other.size && stat.modTime.Equal(other.modTime)
}

// NewWatcher creates and starts a Watcher for the given DynamicStore, checking for changes in the given interval.
func NewWatcher(dynamicStore *DynamicStore, interval time.Duration) *Watcher {
	watcher := &Watcher{
		dynamicStore: dynamicStore,
		done:         make(chan struct{}),
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
			watcher.dynamicStore.Poll()
		}
	}
}
