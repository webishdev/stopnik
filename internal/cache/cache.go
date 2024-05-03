package cache

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

type Cache[T any] struct {
	cacheMap map[string]expiringType[T]
	mux      sync.RWMutex
	ticker   *time.Ticker
}

func NewCache[T any]() *Cache[T] {
	return NewTimedCache[T](time.Minute * time.Duration(1))
}

func NewTimedCache[T any](duration time.Duration) *Cache[T] {
	ticker := time.NewTicker(duration)
	cache := &Cache[T]{
		cacheMap: make(map[string]expiringType[T]),
		mux:      sync.RWMutex{},
		ticker:   ticker,
	}
	go cache.startCleanUp()
	return cache
}

func (currentCache *Cache[T]) startCleanUp() {
	for {
		select {
		case <-currentCache.ticker.C:
			currentCache.cleanUp()
		}
	}
}

func (currentCache *Cache[T]) cleanUp() {
	log.Printf("%s", "Cleaning up")
	if !currentCache.empty() {
		now := time.Now()
		currentCache.mux.RLock()
		for key, value := range currentCache.cacheMap {
			if now.After(value.expireDate) {
				currentCache.mux.RUnlock()
				currentCache.delete(key)
				currentCache.mux.RLock()
			}
		}
		currentCache.mux.RUnlock()
	}
}

func (currentCache *Cache[T]) empty() bool {
	currentCache.mux.RLock()
	defer currentCache.mux.RUnlock()
	return len(currentCache.cacheMap) == 0
}

func (currentCache *Cache[T]) delete(key string) {
	currentCache.mux.Lock()
	defer currentCache.mux.Unlock()
	log.Printf("Removing %s", key)
	delete(currentCache.cacheMap, key)
}

func (currentCache *Cache[T]) Set(key string, value T) {
	currentCache.mux.Lock()
	defer currentCache.mux.Unlock()
	currentCache.cacheMap[key] = expiringType[T]{
		value:      value,
		expireDate: time.Now().Add(time.Minute * time.Duration(5)),
	}
}

func (currentCache *Cache[T]) Get(key string) (T, bool) {
	currentCache.mux.RLock()
	defer currentCache.mux.RUnlock()
	value, exists := currentCache.cacheMap[key]
	return value.value, exists
}
