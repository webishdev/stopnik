package validation

import (
	"sync"
	"time"

	"github.com/webishdev/stopnik/internal/store"
)

const maxFailedAttempts = 10
const failedAttemptsWindow = time.Minute * time.Duration(5)

type failedAttempts struct {
	count int
}

// attemptLimiter blocks further credential checks for a key (e.g. a username or client id)
// after too many failed attempts within a time window, to slow down brute force attacks.
// Keys are counted whether a user or client exists or not, so blocking does not reveal existing users or clients.
type attemptLimiter struct {
	mux         *sync.Mutex
	maxAttempts int
	attempts    store.ExpiringStore[failedAttempts]
}

var credentialLimiter = newAttemptLimiter(maxFailedAttempts, failedAttemptsWindow)

func newAttemptLimiter(maxAttempts int, window time.Duration) *attemptLimiter {
	return &attemptLimiter{
		mux:         &sync.Mutex{},
		maxAttempts: maxAttempts,
		attempts:    store.NewTimedStore[failedAttempts](window),
	}
}

// blocked returns whether further attempts for the given key are currently blocked.
func (limiter *attemptLimiter) blocked(key string) bool {
	limiter.mux.Lock()
	defer limiter.mux.Unlock()
	attempts, exists := limiter.attempts.Get(key)
	return exists && attempts.count >= limiter.maxAttempts
}

// failed records a failed attempt for the given key, the time window starts with the first failed attempt.
func (limiter *attemptLimiter) failed(key string) {
	limiter.mux.Lock()
	defer limiter.mux.Unlock()
	attempts, exists := limiter.attempts.Get(key)
	if exists {
		attempts.count++
	} else {
		limiter.attempts.Set(key, &failedAttempts{count: 1})
	}
}

// succeeded resets the failed attempts for the given key.
func (limiter *attemptLimiter) succeeded(key string) {
	limiter.mux.Lock()
	defer limiter.mux.Unlock()
	limiter.attempts.Delete(key)
}
