package cache

import "sync"

type AuthSession struct {
	Redirect string
	AuthURI  string
}

type Cache[T any] struct {
	cacheMap map[string]T
	mux      sync.RWMutex
}

func NewCache[T any]() *Cache[T] {
	return &Cache[T]{
		cacheMap: make(map[string]T),
		mux:      sync.RWMutex{},
	}
}

func (c *Cache[T]) Set(key string, value T) {
	c.mux.Lock()
	defer c.mux.Unlock()
	c.cacheMap[key] = value
}

func (c *Cache[T]) Get(key string) (T, bool) {
	c.mux.RLock()
	defer c.mux.RUnlock()
	value, exists := c.cacheMap[key]
	return value, exists
}

func (c *Cache[T]) GetAndDelete(key string) (T, bool) {
	c.mux.Lock()
	defer c.mux.Unlock()
	value, exists := c.cacheMap[key]
	delete(c.cacheMap, key)
	return value, exists
}
