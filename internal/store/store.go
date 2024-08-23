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
}

type store[T any] struct {
	storeMap map[string]*T
	mux      *sync.RWMutex
}

type Store[T any] interface {
	Delete(key string)
	Set(key string, value *T)
	Get(key string) (*T, bool)
	GetValues() []*T
}

type ExpiringStore[T any] interface {
	SetWithDuration(key string, value *T, duration time.Duration)
	Store[T]
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

func NewStore[T any]() Store[T] {
	return &store[T]{
		storeMap: make(map[string]*T),
		mux:      &sync.RWMutex{},
	}
}

func NewDefaultTimedStore[T any]() ExpiringStore[T] {
	return NewTimedStore[T](time.Minute * time.Duration(5))
}

func NewTimedStore[T any](duration time.Duration) ExpiringStore[T] {
	return newTimedStoreWithTimer[T](duration, NewTimer())
}

func newTimedStoreWithTimer[T any](duration time.Duration, timer *Timer) ExpiringStore[T] {
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

func (ts *timedStore[T]) startCleanUp() {
	for {
		<-ts.tickerChannel
		ts.cleanUp()
	}
}

func (ts *timedStore[T]) cleanUp() {
	if log.IsDebug() {
		log.Debug("%s - %T", "Cleaning up", *new(T))
	}
	if !ts.empty() {
		now := ts.now()
		ts.mux.RLock()
		for key, value := range ts.storeMap {
			if ts.expired(now, value) {
				ts.mux.RUnlock()
				ts.Delete(key)
				ts.mux.RLock()
			}
		}
		ts.mux.RUnlock()
	}
}

func (ts *timedStore[T]) expiredNow(value expiringType[*T]) bool {
	return ts.expired(ts.now(), value)
}

func (ts *timedStore[T]) expired(time time.Time, value expiringType[*T]) bool {
	return time.After(value.expireDate)
}

func (ts *timedStore[T]) empty() bool {
	ts.mux.RLock()
	defer ts.mux.RUnlock()
	return len(ts.storeMap) == 0
}

func (ts *timedStore[T]) Delete(key string) {
	ts.mux.Lock()
	defer ts.mux.Unlock()
	if log.IsDebug() {
		log.Debug("Removing %s", key)
	}
	delete(ts.storeMap, key)
}

func (ts *timedStore[T]) Set(key string, value *T) {
	ts.SetWithDuration(key, value, ts.duration)
}

func (ts *timedStore[T]) SetWithDuration(key string, value *T, duration time.Duration) {
	ts.mux.Lock()
	defer ts.mux.Unlock()
	ts.storeMap[key] = expiringType[*T]{
		value:      value,
		expireDate: ts.now().Add(duration),
	}
}

func (ts *timedStore[T]) Get(key string) (*T, bool) {
	ts.mux.RLock()
	defer ts.mux.RUnlock()
	value, exists := ts.storeMap[key]
	if ts.expiredNow(value) {
		var none T
		return &none, false
	}
	return value.value, exists
}

func (ts *timedStore[T]) GetValues() []*T {
	ts.mux.RLock()
	defer ts.mux.RUnlock()
	values := make([]*T, 0, len(ts.storeMap))

	for _, value := range ts.storeMap {
		values = append(values, value.value)
	}

	return values
}

func (s *store[T]) Delete(key string) {
	s.mux.Lock()
	defer s.mux.Unlock()
	if log.IsDebug() {
		log.Debug("Removing %s", key)
	}
	delete(s.storeMap, key)
}

func (s *store[T]) Set(key string, value *T) {
	s.mux.Lock()
	defer s.mux.Unlock()
	s.storeMap[key] = value
}

func (s *store[T]) SetWithDuration(key string, value *T, duration time.Duration) {
	s.Set(key, value)
}

func (s *store[T]) Get(key string) (*T, bool) {
	s.mux.RLock()
	defer s.mux.RUnlock()
	value, exists := s.storeMap[key]
	return value, exists
}

func (s *store[T]) GetValues() []*T {
	s.mux.RLock()
	defer s.mux.RUnlock()
	values := make([]*T, 0, len(s.storeMap))

	for _, value := range s.storeMap {
		values = append(values, value)
	}

	return values
}
