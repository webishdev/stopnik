package limiter

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

type testClock struct {
	mutex sync.Mutex
	time  time.Time
}

func newTestClock() *testClock {
	return &testClock{time: time.Date(1979, 1, 17, 15, 0, 0, 0, time.Local)}
}

func (clock *testClock) now() time.Time {
	clock.mutex.Lock()
	defer clock.mutex.Unlock()
	return clock.time
}

func (clock *testClock) add(duration time.Duration) {
	clock.mutex.Lock()
	defer clock.mutex.Unlock()
	clock.time = clock.time.Add(duration)
}

func Test_LimiterBlocksAfterMaxAttempts(t *testing.T) {
	clock := newTestClock()
	limiter := newLimiter("test", time.Minute, 10, clock.now, func(limiter *Limiter) {
		limiter.maxAttempts = 3
	})

	for range 3 {
		if limiter.Blocked("foo") {
			t.Fatal("key should not be blocked before the maximum of attempts")
		}
		limiter.Failed("foo")
	}

	if !limiter.Blocked("foo") {
		t.Error("key should be blocked after the maximum of attempts")
	}
	if limiter.Blocked("bar") {
		t.Error("other keys should not be blocked")
	}

	clock.add(time.Minute + time.Second)
	if limiter.Blocked("foo") {
		t.Error("key should not be blocked after the time window")
	}
}

func Test_LimiterBackoff(t *testing.T) {
	clock := newTestClock()
	limiter := newLimiter("test", time.Minute, 10, clock.now, func(limiter *Limiter) {
		limiter.freeAttempts = 2
		limiter.baseDelay = time.Second
	})

	limiter.Failed("foo")
	if limiter.Blocked("foo") {
		t.Error("free attempts should not be delayed")
	}
	limiter.Failed("foo")
	if !limiter.Blocked("foo") {
		t.Error("attempts after the free attempts should be delayed")
	}
	clock.add(time.Second + time.Millisecond)
	if limiter.Blocked("foo") {
		t.Error("key should not be delayed after the first delay")
	}

	limiter.Failed("foo")
	clock.add(time.Second + time.Millisecond)
	if !limiter.Blocked("foo") {
		t.Error("delay should double with every failed attempt")
	}
	clock.add(time.Second)
	if limiter.Blocked("foo") {
		t.Error("key should not be delayed after the doubled delay")
	}

	for range 20 {
		limiter.Failed("foo")
	}
	clock.add(time.Minute - time.Second)
	if !limiter.Blocked("foo") {
		t.Error("key should still be delayed")
	}
	clock.add(2 * time.Second)
	if limiter.Blocked("foo") {
		t.Error("delay must not exceed the time window")
	}

	limiter.Failed("bar")
	limiter.Failed("bar")
	limiter.Succeeded("bar")
	if limiter.Blocked("bar") {
		t.Error("success should reset the delay")
	}
}

func Test_LimiterCap(t *testing.T) {
	clock := newTestClock()
	limiter := newLimiter("test", time.Minute, 5, clock.now, func(limiter *Limiter) {
		limiter.maxAttempts = 3
	})

	for index := range 10 {
		limiter.Failed(fmt.Sprintf("key%d", index))
	}

	if limiter.Len() != 5 {
		t.Errorf("limiter should not track more than 5 keys, got %d", limiter.Len())
	}
	if !limiter.Blocked("new") {
		t.Error("new keys should be blocked when the limiter is full")
	}
	if limiter.Blocked("key0") {
		t.Error("tracked keys below the maximum of attempts should not be blocked")
	}

	clock.add(time.Minute + time.Second)
	if limiter.Blocked("new") {
		t.Error("expired keys should be removed when the limiter is full")
	}
	limiter.Failed("new")
	if limiter.Len() != 1 {
		t.Errorf("expected only the new key to be tracked, got %d", limiter.Len())
	}
}

func Test_CredentialGuard(t *testing.T) {
	t.Run("Failures from one address do not block another address", func(t *testing.T) {
		guard := newCredentialGuard(newTestClock().now, 100)
		for range 10 {
			guard.Failed("user:foo", "192.0.2.1")
		}
		if !guard.Blocked("user:foo", "192.0.2.1") {
			t.Error("pair should be delayed")
		}
		if guard.Blocked("user:foo", "198.51.100.7") {
			t.Error("other address should not be blocked")
		}
	})

	t.Run("Failures for many usernames block the address", func(t *testing.T) {
		guard := newCredentialGuard(newTestClock().now, 1000)
		for index := range maxAddressAttempts {
			guard.Failed(fmt.Sprintf("user:%d", index), "192.0.2.1")
		}
		if !guard.Blocked("user:foo", "192.0.2.1") {
			t.Error("address should be blocked")
		}
		if guard.Blocked("user:foo", "198.51.100.7") {
			t.Error("other address should not be blocked")
		}
	})

	t.Run("Failures from many addresses block the username", func(t *testing.T) {
		guard := newCredentialGuard(newTestClock().now, 1000)
		for index := range maxKeyAttempts {
			guard.Failed("user:foo", fmt.Sprintf("10.0.%d.%d", index/256, index%256))
		}
		if !guard.Blocked("user:foo", "198.51.100.7") {
			t.Error("username should be blocked after too many failures from all addresses")
		}
		if guard.Blocked("user:bar", "198.51.100.7") {
			t.Error("other usernames should not be blocked")
		}
	})

	t.Run("Guard does not grow past its cap", func(t *testing.T) {
		guard := newCredentialGuard(newTestClock().now, 10)
		for index := range 100 {
			guard.Failed(fmt.Sprintf("user:%d", index), fmt.Sprintf("10.0.0.%d", index))
		}
		if guard.address.Len() > 10 || guard.pair.Len() > 10 || guard.key.Len() > 10 {
			t.Errorf("guard tracks more keys than allowed: %d %d %d", guard.address.Len(), guard.pair.Len(), guard.key.Len())
		}
	})
}
