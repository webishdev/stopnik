package store

import (
	"log"
	"sync"
	"time"
)

type AuthSession struct {
	Redirect string
	AuthURI  string
}

type expiringType[T any] struct {
	value      T
	expireDate time.Time
}

type Store[T any] struct {
	storeMap map[string]expiringType[T]
	mux      sync.RWMutex
	ticker   *time.Ticker
}

func NewCache[T any]() *Store[T] {
	return NewTimedCache[T](time.Minute * time.Duration(1))
}

func NewTimedCache[T any](duration time.Duration) *Store[T] {
	ticker := time.NewTicker(duration)
	cache := &Store[T]{
		storeMap: make(map[string]expiringType[T]),
		mux:      sync.RWMutex{},
		ticker:   ticker,
	}
	go cache.startCleanUp()
	return cache
}

func (currentCache *Store[T]) startCleanUp() {
	for {
		select {
		case <-currentCache.ticker.C:
			currentCache.cleanUp()
		}
	}
}

func (currentCache *Store[T]) cleanUp() {
	log.Printf("%s", "Cleaning up")
	if !currentCache.empty() {
		now := time.Now()
		currentCache.mux.RLock()
		for key, value := range currentCache.storeMap {
			if now.After(value.expireDate) {
				currentCache.mux.RUnlock()
				currentCache.delete(key)
				currentCache.mux.RLock()
			}
		}
		currentCache.mux.RUnlock()
	}
}

func (currentCache *Store[T]) empty() bool {
	currentCache.mux.RLock()
	defer currentCache.mux.RUnlock()
	return len(currentCache.storeMap) == 0
}

func (currentCache *Store[T]) delete(key string) {
	currentCache.mux.Lock()
	defer currentCache.mux.Unlock()
	log.Printf("Removing %s", key)
	delete(currentCache.storeMap, key)
}

func (currentCache *Store[T]) Set(key string, value T) {
	currentCache.mux.Lock()
	defer currentCache.mux.Unlock()
	currentCache.storeMap[key] = expiringType[T]{
		value:      value,
		expireDate: time.Now().Add(time.Minute * time.Duration(5)),
	}
}

func (currentCache *Store[T]) Get(key string) (T, bool) {
	currentCache.mux.RLock()
	defer currentCache.mux.RUnlock()
	value, exists := currentCache.storeMap[key]
	return value.value, exists
}
