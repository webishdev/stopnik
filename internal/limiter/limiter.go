// Package limiter slows down brute force attacks against passwords and client secrets.
package limiter

import (
	"sync"
	"time"

	"github.com/webishdev/stopnik/log"
)

// attempts holds the failed attempts of a single key within the current time window.
type attempts struct {
	count       int
	windowStart time.Time
	lastFailure time.Time
}

// Limiter counts failed attempts per key within a time window.
// A key is blocked after maxAttempts failed attempts, when maxAttempts is greater than zero,
// and after freeAttempts failed attempts for an exponentially growing delay, when baseDelay is greater than zero.
// The number of tracked keys is limited by maxKeys, as keys are controlled by clients.
// When the limit is reached, new keys are blocked until older keys expire.
type Limiter struct {
	name         string
	mutex        sync.Mutex
	now          func() time.Time
	window       time.Duration
	maxAttempts  int
	freeAttempts int
	baseDelay    time.Duration
	maxKeys      int
	attempts     map[string]*attempts
	fullLoggedAt time.Time
}

// NewLimiter creates a Limiter which blocks a key after maxAttempts failed attempts within the window.
func NewLimiter(name string, maxAttempts int, window time.Duration, maxKeys int) *Limiter {
	return newLimiter(name, window, maxKeys, time.Now, func(limiter *Limiter) {
		limiter.maxAttempts = maxAttempts
	})
}

// NewBackoffLimiter creates a Limiter which delays further attempts for a key after freeAttempts failed attempts,
// the delay starts with baseDelay and doubles with every further failed attempt, but never exceeds the window.
func NewBackoffLimiter(name string, freeAttempts int, baseDelay time.Duration, window time.Duration, maxKeys int) *Limiter {
	return newLimiter(name, window, maxKeys, time.Now, func(limiter *Limiter) {
		limiter.freeAttempts = freeAttempts
		limiter.baseDelay = baseDelay
	})
}

func newLimiter(name string, window time.Duration, maxKeys int, now func() time.Time, configure func(limiter *Limiter)) *Limiter {
	limiter := &Limiter{
		name:     name,
		now:      now,
		window:   window,
		maxKeys:  maxKeys,
		attempts: make(map[string]*attempts),
	}
	configure(limiter)
	return limiter
}

// Blocked returns whether further attempts for the given key are currently blocked.
func (limiter *Limiter) Blocked(key string) bool {
	limiter.mutex.Lock()
	defer limiter.mutex.Unlock()
	now := limiter.now()
	current, exists := limiter.current(key, now)
	if !exists {
		return limiter.full(now)
	}
	if limiter.maxAttempts > 0 && current.count >= limiter.maxAttempts {
		return true
	}
	if limiter.baseDelay > 0 && current.count >= limiter.freeAttempts {
		return now.Before(current.lastFailure.Add(limiter.delay(current.count)))
	}
	return false
}

// Failed records a failed attempt for the given key, the time window starts with the first failed attempt.
func (limiter *Limiter) Failed(key string) {
	limiter.mutex.Lock()
	defer limiter.mutex.Unlock()
	now := limiter.now()
	current, exists := limiter.current(key, now)
	if !exists {
		if limiter.full(now) {
			return
		}
		current = &attempts{windowStart: now}
		limiter.attempts[key] = current
	}
	current.count++
	current.lastFailure = now
}

// Succeeded resets the failed attempts for the given key.
func (limiter *Limiter) Succeeded(key string) {
	limiter.mutex.Lock()
	defer limiter.mutex.Unlock()
	delete(limiter.attempts, key)
}

// Len returns the number of currently tracked keys.
func (limiter *Limiter) Len() int {
	limiter.mutex.Lock()
	defer limiter.mutex.Unlock()
	return len(limiter.attempts)
}

// current returns the attempts of the key, when they are not expired.
func (limiter *Limiter) current(key string, now time.Time) (*attempts, bool) {
	current, exists := limiter.attempts[key]
	if !exists {
		return nil, false
	}
	if limiter.expired(current, now) {
		delete(limiter.attempts, key)
		return nil, false
	}
	return current, true
}

// expired returns whether the time window of the attempts is over.
// For a backoff the window is extended by the last failure, so the delay is never shorter than intended.
func (limiter *Limiter) expired(current *attempts, now time.Time) bool {
	windowEnd := current.windowStart.Add(limiter.window)
	if limiter.baseDelay > 0 {
		windowEnd = current.lastFailure.Add(limiter.window)
	}
	return now.After(windowEnd)
}

// full returns whether no further keys can be tracked, expired keys are removed first.
func (limiter *Limiter) full(now time.Time) bool {
	if len(limiter.attempts) < limiter.maxKeys {
		return false
	}
	for key, current := range limiter.attempts {
		if limiter.expired(current, now) {
			delete(limiter.attempts, key)
		}
	}
	if len(limiter.attempts) < limiter.maxKeys {
		return false
	}
	// logged at most once per window, so an attack does not flood the log
	if now.After(limiter.fullLoggedAt.Add(limiter.window)) {
		log.Error("Limiter %s tracks the maximum of %d keys, new keys are blocked", limiter.name, limiter.maxKeys)
		limiter.fullLoggedAt = now
	}
	return true
}

// delay returns the delay after the given number of failed attempts.
func (limiter *Limiter) delay(count int) time.Duration {
	delay := limiter.baseDelay
	for range count - limiter.freeAttempts {
		delay *= 2
		if delay >= limiter.window {
			return limiter.window
		}
	}
	return delay
}
