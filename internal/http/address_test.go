package http

import (
	"net/http/httptest"
	"net/netip"
	"testing"
)

func Test_ClientAddress(t *testing.T) {
	trustedProxies := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("::1/128"),
	}

	type addressParameter struct {
		name            string
		remoteAddr      string
		forwardedFor    []string
		trustedProxies  []netip.Prefix
		expectedAddress string
	}

	var addressParameters = []addressParameter{
		{"Direct peer", "192.0.2.1:1234", nil, nil, "192.0.2.1"},
		{"Forwarded for ignored without trusted proxies", "192.0.2.1:1234", []string{"198.51.100.7"}, nil, "192.0.2.1"},
		{"Forwarded for ignored from untrusted peer", "192.0.2.1:1234", []string{"198.51.100.7"}, trustedProxies, "192.0.2.1"},
		{"Forwarded for from trusted peer", "10.0.0.1:1234", []string{"198.51.100.7"}, trustedProxies, "198.51.100.7"},
		{"Right-most untrusted address", "10.0.0.1:1234", []string{"203.0.113.9, 198.51.100.7, 10.0.0.2"}, trustedProxies, "198.51.100.7"},
		{"Multiple headers", "10.0.0.1:1234", []string{"203.0.113.9", "198.51.100.7"}, trustedProxies, "198.51.100.7"},
		{"Spoofed left-most address is ignored", "10.0.0.1:1234", []string{"1.2.3.4, 198.51.100.7"}, trustedProxies, "198.51.100.7"},
		{"Invalid entry stops", "10.0.0.1:1234", []string{"198.51.100.7, garbage"}, trustedProxies, "10.0.0.1"},
		{"IPv6 trusted peer", "[::1]:1234", []string{"2001:db8::1"}, trustedProxies, "2001:db8::1"},
		{"Only trusted addresses", "10.0.0.1:1234", []string{"10.0.0.3"}, trustedProxies, "10.0.0.3"},
	}

	for _, test := range addressParameters {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest("GET", "/", nil)
			request.RemoteAddr = test.remoteAddr
			for _, forwardedFor := range test.forwardedFor {
				request.Header.Add(XForwardedFor, forwardedFor)
			}
			if address := ClientAddress(request, test.trustedProxies); address != test.expectedAddress {
				t.Errorf("address %s did not match %s", address, test.expectedAddress)
			}
		})
	}
}

func Test_ParseTrustedProxy(t *testing.T) {
	type proxyParameter struct {
		value          string
		expectedPrefix string
		valid          bool
	}

	var proxyParameters = []proxyParameter{
		{"10.0.0.0/8", "10.0.0.0/8", true},
		{"10.1.2.3/8", "10.0.0.0/8", true},
		{"10.0.0.1", "10.0.0.1/32", true},
		{"::1", "::1/128", true},
		{"fd00::/8", "fd00::/8", true},
		{"foo", "", false},
		{"10.0.0.0/99", "", false},
	}

	for _, test := range proxyParameters {
		t.Run(test.value, func(t *testing.T) {
			prefix, parseError := ParseTrustedProxy(test.value)
			if test.valid && (parseError != nil || prefix.String() != test.expectedPrefix) {
				t.Errorf("expected %s, got %s %v", test.expectedPrefix, prefix, parseError)
			}
			if !test.valid && parseError == nil {
				t.Errorf("expected %s to be invalid", test.value)
			}
		})
	}
}
