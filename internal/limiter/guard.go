package limiter

import "time"

const (
	// guardWindow is the time window in which failed attempts are counted.
	guardWindow = time.Minute * time.Duration(5)
	// maxAddressAttempts limits the failed attempts per source address, independent of the username or client id.
	maxAddressAttempts = 50
	// maxKeyAttempts limits the failed attempts per username or client id from all addresses, as a backstop.
	maxKeyAttempts = 100
	// freePairAttempts are the failed attempts per username or client id and address without delay.
	freePairAttempts = 3
	// pairBaseDelay is the first delay after the free attempts, it doubles with every further failed attempt.
	pairBaseDelay = time.Second
	// maxTrackedKeys limits the number of keys tracked by each limiter.
	maxTrackedKeys = 100000
)

// CredentialGuard slows down brute force attacks against credentials.
//   - Failed attempts of a username or client id from one address delay further attempts of this pair exponentially,
//     so an attacker can not lock out a user, which signs in from another address.
//   - Too many failed attempts from one address block the address, so one address can not try many usernames.
//   - Too many failed attempts for a username or client id from all addresses block the username or client id.
//
// Keys are counted whether a user or client exists or not, so blocking does not reveal existing users or clients.
type CredentialGuard struct {
	address *Limiter
	pair    *Limiter
	key     *Limiter
}

// NewCredentialGuard creates a CredentialGuard with the default limits.
func NewCredentialGuard() *CredentialGuard {
	return newCredentialGuard(time.Now, maxTrackedKeys)
}

func newCredentialGuard(now func() time.Time, maxKeys int) *CredentialGuard {
	return &CredentialGuard{
		address: newLimiter("address", guardWindow, maxKeys, now, func(limiter *Limiter) {
			limiter.maxAttempts = maxAddressAttempts
		}),
		pair: newLimiter("pair", guardWindow, maxKeys, now, func(limiter *Limiter) {
			limiter.freeAttempts = freePairAttempts
			limiter.baseDelay = pairBaseDelay
		}),
		key: newLimiter("key", guardWindow, maxKeys, now, func(limiter *Limiter) {
			limiter.maxAttempts = maxKeyAttempts
		}),
	}
}

// Blocked returns whether an attempt for the given key (e.g. a username or client id) from the given address is blocked.
func (guard *CredentialGuard) Blocked(key string, address string) bool {
	return guard.address.Blocked(address) || guard.pair.Blocked(pairKey(key, address)) || guard.key.Blocked(key)
}

// Failed records a failed attempt for the given key from the given address.
func (guard *CredentialGuard) Failed(key string, address string) {
	guard.address.Failed(address)
	guard.pair.Failed(pairKey(key, address))
	guard.key.Failed(key)
}

// Succeeded resets the delay for the given key from the given address.
// The counters of the address and the key are kept, so a successful attempt with own credentials
// does not allow further attempts against other users.
func (guard *CredentialGuard) Succeeded(key string, address string) {
	guard.pair.Succeeded(pairKey(key, address))
}

func pairKey(key string, address string) string {
	return key + "\x00" + address
}
