package assert

import (
	"reflect"
	"testing"
)

func Equal(t *testing.T, a interface{}, b interface{}) {
	if !reflect.DeepEqual(a, b) {
		t.Errorf("assertion error, %v != %v", a, b)
	}
}
