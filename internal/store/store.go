package store

import (
	"github.com/webishdev/stopnik/log"
	"sync"
	"time"
)

type Now func() time.Time
type TickerChannel func() <-chan time.Time

type Timer struct {
	now           Now
	tickerChannel TickerChannel
}

type expiringType[T any] struct {
	value      T
	expireDate time.Time
}

type timedStore[T any] struct {
	storeMap      map[string]expiringType[*T]
	mux           *sync.RWMutex
	tickerChannel <-chan time.Time
	now           Now
	duration      time.Duration
	Store[T]
}

type store[T any] struct {
	storeMap map[string]*T
	Store[T]
}

type Store[T any] interface {
	Delete(key string)
	Set(key string, value *T)
	SetWithDuration(key string, value *T, duration time.Duration)
	Get(key string) (*T, bool)
	GetValues() []*T
}

func NewTimer() *Timer {
	channel := time.NewTicker(time.Minute * time.Duration(1)).C
	return &Timer{
		now: time.Now,
		tickerChannel: func() <-chan time.Time {
			return channel
		},
	}
}

func NewDefaultTimedStore[T any]() Store[T] {
	return NewTimedStore[T](time.Minute * time.Duration(5))
}

func NewTimedStore[T any](duration time.Duration) Store[T] {
	return newTimedStoreWithTimer[T](duration, NewTimer())
}

func newTimedStoreWithTimer[T any](duration time.Duration, timer *Timer) Store[T] {
	tickerChannel := timer.tickerChannel()
	cache := &timedStore[T]{
		storeMap:      make(map[string]expiringType[*T]),
		mux:           &sync.RWMutex{},
		tickerChannel: tickerChannel,
		now:           timer.now,
		duration:      duration,
	}
	go cache.startCleanUp()
	return cache
}

func (currentCache *timedStore[T]) startCleanUp() {
	for {
		<-currentCache.tickerChannel
		currentCache.cleanUp()
	}
}

func (currentCache *timedStore[T]) cleanUp() {
	if log.IsDebug() {
		log.Debug("%s - %T", "Cleaning up", *new(T))
	}
	if !currentCache.empty() {
		now := currentCache.now()
		currentCache.mux.RLock()
		for key, value := range currentCache.storeMap {
			if currentCache.expired(now, value) {
				currentCache.mux.RUnlock()
				currentCache.Delete(key)
				currentCache.mux.RLock()
			}
		}
		currentCache.mux.RUnlock()
	}
}

func (currentCache *timedStore[T]) expiredNow(value expiringType[*T]) bool {
	return currentCache.expired(currentCache.now(), value)
}

func (currentCache *timedStore[T]) expired(time time.Time, value expiringType[*T]) bool {
	return time.After(value.expireDate)
}

func (currentCache *timedStore[T]) empty() bool {
	currentCache.mux.RLock()
	defer currentCache.mux.RUnlock()
	return len(currentCache.storeMap) == 0
}

func (currentCache *timedStore[T]) Delete(key string) {
	currentCache.mux.Lock()
	defer currentCache.mux.Unlock()
	if log.IsDebug() {
		log.Debug("Removing %s", key)
	}
	delete(currentCache.storeMap, key)
}

func (currentCache *timedStore[T]) Set(key string, value *T) {
	currentCache.SetWithDuration(key, value, currentCache.duration)
}

func (currentCache *timedStore[T]) SetWithDuration(key string, value *T, duration time.Duration) {
	currentCache.mux.Lock()
	defer currentCache.mux.Unlock()
	currentCache.storeMap[key] = expiringType[*T]{
		value:      value,
		expireDate: currentCache.now().Add(duration),
	}
}

func (currentCache *timedStore[T]) Get(key string) (*T, bool) {
	currentCache.mux.RLock()
	defer currentCache.mux.RUnlock()
	value, exists := currentCache.storeMap[key]
	if currentCache.expiredNow(value) {
		var none T
		return &none, false
	}
	return value.value, exists
}

func (currentCache *timedStore[T]) GetValues() []*T {
	currentCache.mux.RLock()
	defer currentCache.mux.RUnlock()
	values := make([]*T, 0, len(currentCache.storeMap))

	for _, value := range currentCache.storeMap {
		values = append(values, value.value)
	}

	return values
}
