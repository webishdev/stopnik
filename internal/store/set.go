package store

import (
	"bytes"
	"crypto/sha1"
	"encoding/gob"
	"fmt"
	"log"
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
	key := s.createKey(item)
	s.values[key] = item
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
	key := s.createKey(item)
	delete(s.values, key)
}

func (s *set[T]) Clear() {
	s.mux.Lock()
	defer s.mux.Unlock()
	s.values = make(map[string]*T)
}

func (s *set[T]) Contains(item *T) bool {
	s.mux.RLock()
	defer s.mux.RUnlock()
	key := s.createKey(item)
	return s.values[key] != nil
}

func (s *set[T]) IsEmpty() bool {
	s.mux.RLock()
	defer s.mux.RUnlock()
	return len(s.values) == 0
}

func (s *set[T]) createKey(item *T) string {
	x := *item
	switch reflect.TypeOf(x).Kind() {
	case reflect.String:
		return fmt.Sprintf("%v", x)
	default:
		encBuf := new(bytes.Buffer)
		err := gob.NewEncoder(encBuf).Encode(*item)
		if err != nil {
			log.Fatal(err)
		}
		value := encBuf.Bytes()
		return fmt.Sprintf("%x", sha1.Sum(value))
	}

}
