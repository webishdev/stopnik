package store

import "testing"

func Test_SetWithString(t *testing.T) {
	current := NewSet[string]()
	text := "hello"

	if !current.IsEmpty() {
		t.Error("expected set to be empty")
	}

	current.Add(&text)

	if !current.Contains(&text) {
		t.Error("expected set to contain value")
	}

	if current.IsEmpty() {
		t.Error("expected set to not be empty")
	}

	current.Remove(&text)

	if current.Contains(&text) {
		t.Error("expected set to not contain value")
	}

	if !current.IsEmpty() {
		t.Error("expected set to be empty")
	}

	current.Add(&text)

	values := current.GetAll()

	if len(values) != 1 {
		t.Error("expected set to contain only one value")
	}

	current.Clear()

	if !current.IsEmpty() {
		t.Error("expected set to be empty")
	}
}

func Test_SetWithStruct(t *testing.T) {
	type foo struct {
		Name  string
		Value int
	}
	current := NewSet[foo]()
	fooValue := foo{
		Name:  "foo",
		Value: 42,
	}

	if !current.IsEmpty() {
		t.Error("expected set to be empty")
	}

	current.Add(&fooValue)

	if !current.Contains(&fooValue) {
		t.Error("expected set to contain value")
	}

	if current.IsEmpty() {
		t.Error("expected set to not be empty")
	}

	current.Remove(&fooValue)

	if current.Contains(&fooValue) {
		t.Error("expected set to not contain value")
	}

	if !current.IsEmpty() {
		t.Error("expected set to be empty")
	}

	current.Add(&fooValue)

	values := current.GetAll()

	if len(values) != 1 {
		t.Error("expected set to contain only one value")
	}

	current.Clear()

	if !current.IsEmpty() {
		t.Error("expected set to be empty")
	}
}
