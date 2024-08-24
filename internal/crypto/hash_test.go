package crypto

import (
	"testing"
)

func Test_Sha512Hash(t *testing.T) {
	type parameter struct {
		value    string
		expected string
	}

	var parameters = []parameter{
		{"foo", "f7fbba6e0636f890e56fbbf3283e524c6fa3204ae298382d624741d0dc6638326e282c41be5e4254d8820772c5518a2c5a8c0c7f7eda19594a7eb539453e1ed7"},
		{"bar", "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181"},
		{"moo123", "c946fb5c9b11f7fbe62811cb62a84c94bbfc5663a0b99aaa353b2342805d6bceb70d12e65420806e55b0ba6d02609a95bb517c9cc215eb6925f196ba5d9674b0"},
	}

	for _, test := range parameters {
		testMessage := test.value
		t.Run(testMessage, func(t *testing.T) {
			if output := Sha512Hash(test.value); output != test.expected {
				t.Errorf("Output %s not equal to expected %s", output, test.expected)
			}
		})
	}
}

func Test_Sha512SaltedHash(t *testing.T) {
	type parameter struct {
		value    string
		salt     string
		expected string
	}

	var parameters = []parameter{
		{"foo", "123", "f67d590227678ab69f880dcaab6dd95b312bde973ba7ef00286f09e4e3229c8492129e12f8dd6421de22dbbb25e261548bed18e70eec271fbca9029a78d5f06c"},
		{"foo", "", "f7fbba6e0636f890e56fbbf3283e524c6fa3204ae298382d624741d0dc6638326e282c41be5e4254d8820772c5518a2c5a8c0c7f7eda19594a7eb539453e1ed7"},
		{"bar", "moo", "695e6f39f5ffd36ae60e0ade727c892d725531455a19c6035cb739d099e8f20e63d3fdfd3241888e38de1d8db85532dd65f817b12fe33ac7cdcc358ef6c8ea23"},
		{"bar", "", "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181"},
		{"moo123", "xyz", "0072242c58c82b487152f5fd0692ee7952c840ced6b35bf4093c9d027e4301120543813e4f7313c6c88a8d6fa2d2fa25ada0dc84a00d792191530c489995bade"},
	}

	for _, test := range parameters {
		testMessage := test.value
		t.Run(testMessage, func(t *testing.T) {
			if output := Sha512SaltedHash(test.value, test.salt); output != test.expected {
				t.Errorf("Output %s not equal to expected %s", output, test.expected)
			}
		})
	}
}

func Test_Sha1Hash(t *testing.T) {
	type parameter struct {
		value    string
		expected string
	}

	var parameters = []parameter{
		{"foo", "0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33"},
		{"bar", "62cdb7020ff920e5aa642c3d4066950dd1f01f4d"},
		{"moo123", "36d0e94568d34adaec89601e4297a10100cf47c5"},
	}

	for _, test := range parameters {
		testMessage := test.value
		t.Run(testMessage, func(t *testing.T) {
			if output := Sha1Hash(test.value); output != test.expected {
				t.Errorf("Output %s not equal to expected %s", output, test.expected)
			}
		})
	}
}
