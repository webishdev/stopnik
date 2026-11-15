package admin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/crypto"
	internalStore "github.com/webishdev/stopnik/internal/store"
)

const sessionCookieName = "stopnik_admin_session"
const defaultSessionTimeout = time.Hour
const maxFailedLogins = 10
const failedLoginsWindow = time.Minute * time.Duration(5)

// ErrOwnAdmin is returned when the signed-in administrator would lock themselves out.
var ErrOwnAdmin = errors.New("you can not delete, rename or remove the administrator flag of your own user")

type adminSession struct {
	username string
}

type failedLogins struct {
	count int
}

type usernameKey struct{}

// authenticator signs in users which are allowed to use the admin web user interface.
// Sessions are kept in memory, restarting the admin web user interface signs out all users.
type authenticator struct {
	store          *Store
	sessionTimeout time.Duration
	sessions       internalStore.ExpiringStore[adminSession]
	mutex          sync.Mutex
	failed         internalStore.ExpiringStore[failedLogins]
}

func newAuthenticator(store *Store, sessionTimeout time.Duration) *authenticator {
	return &authenticator{
		store:          store,
		sessionTimeout: sessionTimeout,
		sessions:       internalStore.NewTimedStore[adminSession](sessionTimeout),
		failed:         internalStore.NewTimedStore[failedLogins](failedLoginsWindow),
	}
}

// login checks the credentials and returns a new session token for an administrator.
// After too many failed attempts within a time window further attempts for the username are rejected,
// whether the user exists or not.
func (auth *authenticator) login(username string, password string) (string, bool) {
	if auth.blocked(username) {
		return "", false
	}
	user := auth.store.FindUser(username)
	expectedHash, salt := "", ""
	if user != nil {
		expectedHash, salt = user.Password, user.Salt
	}
	// the secret is verified for unknown users too, so the response time does not reveal existing users
	validSecret := crypto.VerifySecret(password, salt, expectedHash)
	if !validSecret || user == nil || !user.Admin {
		auth.failedAttempt(username)
		return "", false
	}
	auth.mutex.Lock()
	auth.failed.Delete(username)
	auth.mutex.Unlock()

	token := make([]byte, 32)
	if _, randError := rand.Read(token); randError != nil {
		return "", false
	}
	sessionId := hex.EncodeToString(token)
	auth.sessions.Set(sessionId, &adminSession{username: username})
	return sessionId, true
}

// user returns the administrator of the session cookie.
// The user is loaded on every request, so removing the administrator flag or the user ends existing sessions.
func (auth *authenticator) user(r *http.Request) (*config.User, bool) {
	cookie, cookieError := r.Cookie(sessionCookieName)
	if cookieError != nil {
		return nil, false
	}
	session, exists := auth.sessions.Get(cookie.Value)
	if !exists {
		return nil, false
	}
	user := auth.store.FindUser(session.username)
	if user == nil || !user.Admin {
		auth.sessions.Delete(cookie.Value)
		return nil, false
	}
	return user, true
}

// logout ends the session of the session cookie.
func (auth *authenticator) logout(r *http.Request) {
	if cookie, cookieError := r.Cookie(sessionCookieName); cookieError == nil {
		auth.sessions.Delete(cookie.Value)
	}
}

func (auth *authenticator) blocked(username string) bool {
	auth.mutex.Lock()
	defer auth.mutex.Unlock()
	attempts, exists := auth.failed.Get(username)
	return exists && attempts.count >= maxFailedLogins
}

// failedAttempt records a failed attempt, the time window starts with the first failed attempt.
func (auth *authenticator) failedAttempt(username string) {
	auth.mutex.Lock()
	defer auth.mutex.Unlock()
	if attempts, exists := auth.failed.Get(username); exists {
		attempts.count++
	} else {
		auth.failed.Set(username, &failedLogins{count: 1})
	}
}

// sessionCookie returns the session cookie for the given value, a negative maxAge removes the cookie.
func sessionCookie(r *http.Request, basePath string, value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     basePath + "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
	}
}

// withUsername stores the username of the signed-in administrator in the request.
func withUsername(r *http.Request, username string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), usernameKey{}, username))
}

// signedIn returns the username of the signed-in administrator, empty when nobody is signed in.
func signedIn(r *http.Request) string {
	username, _ := r.Context().Value(usernameKey{}).(string)
	return username
}
