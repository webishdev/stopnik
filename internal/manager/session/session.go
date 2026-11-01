package session

type Manager[T any] interface {
	StartSession(session *T)
	GetSession(id string) (*T, bool)
	DeleteSession(id string)
	TakeSession(id string) (*T, bool)
	SessionCount() int
}
