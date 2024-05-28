package store

import (
	"reflect"
	"testing"
	"time"
)

func Test_Store(t *testing.T) {
	type Tester struct {
		name string
		nice bool
	}

	var mockedTime = time.Date(1979, 1, 17, 15, 0, 0, 0, time.Local)
	var mockedTickerChannel = make(chan time.Time, 1)

	now := func() time.Time {
		return mockedTime
	}

	tickerChannel := func() <-chan time.Time {
		return mockedTickerChannel
	}

	var timer = &Timer{
		now:           now,
		tickerChannel: tickerChannel,
	}

	tester := &Tester{
		name: "foo",
		nice: true,
	}

	t.Run("Set and get", func(t *testing.T) {
		store := newTimedStoreWithTimer[Tester](time.Hour*time.Duration(1), timer)

		store.Set("foo", tester)
		store.SetWithDuration("bar", tester, time.Hour*time.Duration(10))

		fooValueFromStore, fooValueExists := store.Get("foo")

		if !fooValueExists {
			t.Error("value did not exist in store")
		}

		if !reflect.DeepEqual(fooValueFromStore, tester) {
			t.Error("value did not match")
		}

		barValueFromStore, barValueExists := store.Get("bar")

		if !barValueExists {
			t.Error("value did not exist in store")
		}

		if !reflect.DeepEqual(barValueFromStore, tester) {
			t.Error("value did not match")
		}

		mockedTickerChannel <- time.Now()
		mockedTickerChannel <- time.Now()
		mockedTickerChannel <- time.Now()

		mockedTime = mockedTime.Add(time.Hour * time.Duration(5))
		mockedTickerChannel <- time.Now()

		_, fooValueExists = store.Get("foo")

		if fooValueExists {
			t.Error("value did exist in store after expiration")
		}

		_, barValueExists = store.Get("bar")

		if !barValueExists {
			t.Error("value did not exist in store")
		}
	})

	t.Run("Set, get and delete", func(t *testing.T) {
		store := newTimedStoreWithTimer[Tester](time.Hour*time.Duration(1), timer)

		store.Set("foo", tester)
		store.SetWithDuration("bar", tester, time.Hour*time.Duration(10))

		fooValueFromStore, fooValueExists := store.Get("foo")

		if !fooValueExists {
			t.Error("value did not exist in store")
		}

		if !reflect.DeepEqual(fooValueFromStore, tester) {
			t.Error("value did not match")
		}

		store.Delete("foo")

		_, fooValueExists = store.Get("foo")

		if fooValueExists {
			t.Error("value did exist in store after expiration")
		}
	})
}
