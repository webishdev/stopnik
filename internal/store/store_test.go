package store

import (
	"reflect"
	"sync"
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

	rwMutex := &sync.RWMutex{}

	now := func() time.Time {
		rwMutex.RLock()
		defer rwMutex.RUnlock()
		return mockedTime
	}

	addTime := func(d time.Duration) {
		rwMutex.Lock()
		defer rwMutex.Unlock()
		mockedTime = mockedTime.Add(d)
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

	t.Run("Set, get and delete", func(t *testing.T) {
		simpleStore := NewStore[Tester]()

		simpleStore.Set("foo", tester)
		simpleStore.SetWithDuration("bar", tester, time.Hour*time.Duration(10))

		fooValueFromStore, fooValueExists := simpleStore.Get("foo")

		if !fooValueExists {
			t.Error("value did not exist in store")
		}

		if !reflect.DeepEqual(fooValueFromStore, tester) {
			t.Error("value did not match")
		}

		values := simpleStore.GetValues()
		if len(values) != 2 {
			t.Error("amount of values did not match")
		}

		simpleStore.Delete("foo")

		_, fooValueExists = simpleStore.Get("foo")

		if fooValueExists {
			t.Error("value did exist in store after delete")
		}

		values = simpleStore.GetValues()
		if len(values) != 1 {
			t.Error("amount of values did not match")
		}
	})

	t.Run("Set and get for expiring store", func(t *testing.T) {
		storeWithTimer := newTimedStoreWithTimer[Tester](time.Hour*time.Duration(1), timer)

		storeWithTimer.Set("foo", tester)
		storeWithTimer.SetWithDuration("bar", tester, time.Hour*time.Duration(10))

		fooValueFromStore, fooValueExists := storeWithTimer.Get("foo")

		if !fooValueExists {
			t.Error("value did not exist in store")
		}

		if !reflect.DeepEqual(fooValueFromStore, tester) {
			t.Error("value did not match")
		}

		barValueFromStore, barValueExists := storeWithTimer.Get("bar")

		if !barValueExists {
			t.Error("value did not exist in store")
		}

		if !reflect.DeepEqual(barValueFromStore, tester) {
			t.Error("value did not match")
		}

		mockedTickerChannel <- time.Now()
		mockedTickerChannel <- time.Now()
		mockedTickerChannel <- time.Now()

		addTime(time.Hour * time.Duration(5))
		mockedTickerChannel <- time.Now()

		_, fooValueExists = storeWithTimer.Get("foo")

		if fooValueExists {
			t.Error("value did exist in store after expiration")
		}

		_, barValueExists = storeWithTimer.Get("bar")

		if !barValueExists {
			t.Error("value did not exist in store")
		}
	})

	t.Run("Set, get and delete for expiring store", func(t *testing.T) {
		storeWithTimer := newTimedStoreWithTimer[Tester](time.Hour*time.Duration(1), timer)

		storeWithTimer.Set("foo", tester)
		storeWithTimer.SetWithDuration("bar", tester, time.Hour*time.Duration(10))

		fooValueFromStore, fooValueExists := storeWithTimer.Get("foo")

		if !fooValueExists {
			t.Error("value did not exist in store")
		}

		if !reflect.DeepEqual(fooValueFromStore, tester) {
			t.Error("value did not match")
		}

		values := storeWithTimer.GetValues()
		if len(values) != 2 {
			t.Error("amount of values did not match")
		}

		storeWithTimer.Delete("foo")

		_, fooValueExists = storeWithTimer.Get("foo")

		if fooValueExists {
			t.Error("value did exist in store after delete")
		}

		values = storeWithTimer.GetValues()
		if len(values) != 1 {
			t.Error("amount of values did not match")
		}
	})
}
