package store

import (
	"bytes"
	"crypto/sha1"
	"encoding/gob"
	"fmt"
	"reflect"
	"sync"
)

type set[T any] struct {
	values map[string]*T
	mux    *sync.RWMutex
}

type Set[T any] interface {
	Add(item *T)
	GetAll() []*T
	Remove(item *T)
	Clear()
	Contains(item *T) bool
	IsEmpty() bool
}

func NewSet[T any]() Set[T] {
	return &set[T]{
		values: make(map[string]*T),
		mux:    &sync.RWMutex{},
	}
}

func (s *set[T]) Add(item *T) {
	s.mux.Lock()
	defer s.mux.Unlock()
	key, err := s.createKey(item)
	if err == nil {
		s.values[key] = item
	}
}

func (s *set[T]) GetAll() []*T {
	s.mux.RLock()
	defer s.mux.RUnlock()
	result := make([]*T, 0, len(s.values))

	for _, value := range s.values {
		result = append(result, value)
	}

	return result
}

func (s *set[T]) Remove(item *T) {
	s.mux.Lock()
	defer s.mux.Unlock()
	key, err := s.createKey(item)
	if err == nil {
		delete(s.values, key)
	}
}

func (s *set[T]) Clear() {
	s.mux.Lock()
	defer s.mux.Unlock()
	s.values = make(map[string]*T)
}

func (s *set[T]) Contains(item *T) bool {
	s.mux.RLock()
	defer s.mux.RUnlock()
	key, err := s.createKey(item)
	if err == nil {
		return s.values[key] != nil
	}
	return false
}

func (s *set[T]) IsEmpty() bool {
	s.mux.RLock()
	defer s.mux.RUnlock()
	return len(s.values) == 0
}

func (s *set[T]) createKey(item *T) (string, error) {
	x := *item
	switch reflect.TypeOf(x).Kind() {
	case reflect.String:
		return fmt.Sprintf("%v", x), nil
	default:
		encBuf := new(bytes.Buffer)
		err := gob.NewEncoder(encBuf).Encode(*item)
		if err != nil {
			return "", err
		}
		value := encBuf.Bytes()
		return fmt.Sprintf("%x", sha1.Sum(value)), nil
	}

}
