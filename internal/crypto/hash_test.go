package crypto

import (
	"fmt"
	"testing"
)

type parameter struct {
	value    string
	expected string
}

var parameters = []parameter{
	{"foo", "f7fbba6e0636f890e56fbbf3283e524c6fa3204ae298382d624741d0dc6638326e282c41be5e4254d8820772c5518a2c5a8c0c7f7eda19594a7eb539453e1ed7"},
	{"bar", "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181"},
	{"moo123", "c946fb5c9b11f7fbe62811cb62a84c94bbfc5663a0b99aaa353b2342805d6bceb70d12e65420806e55b0ba6d02609a95bb517c9cc215eb6925f196ba5d9674b0"},
}

func Test_Sha512Hash(t *testing.T) {

	for _, test := range parameters {
		testMessage := fmt.Sprintf("%s", test.value)
		t.Run(testMessage, func(t *testing.T) {
			if output := Sha512Hash(test.value); output != test.expected {
				t.Errorf("Output %s not equal to expected %s", output, test.expected)
			}
		})
	}
}
