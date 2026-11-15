package http

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// ClientAddress returns the IP address of the client which sent the request.
// The address of the direct peer is used, X-Forwarded-For is only used when the direct peer is a trusted proxy,
// then the right-most address in X-Forwarded-For which is not a trusted proxy itself is the client address.
func ClientAddress(r *http.Request, trustedProxies []netip.Prefix) string {
	peerAddress := r.RemoteAddr
	host, _, splitError := net.SplitHostPort(r.RemoteAddr)
	if splitError == nil {
		peerAddress = host
	}

	peer, parseError := netip.ParseAddr(peerAddress)
	if parseError != nil || !isTrustedProxy(peer, trustedProxies) {
		return peerAddress
	}

	var forwardedAddresses []string
	for _, forwardedFor := range r.Header.Values(XForwardedFor) {
		forwardedAddresses = append(forwardedAddresses, strings.Split(forwardedFor, ",")...)
	}

	clientAddress := peer
	for index := len(forwardedAddresses) - 1; index >= 0; index-- {
		forwardedAddress, forwardedParseError := netip.ParseAddr(strings.TrimSpace(forwardedAddresses[index]))
		if forwardedParseError != nil {
			// an invalid entry can not be trusted, the last valid address is used
			break
		}
		clientAddress = forwardedAddress.Unmap()
		if !isTrustedProxy(clientAddress, trustedProxies) {
			break
		}
	}
	return clientAddress.String()
}

func isTrustedProxy(address netip.Addr, trustedProxies []netip.Prefix) bool {
	address = address.Unmap()
	for _, trustedProxy := range trustedProxies {
		if trustedProxy.Contains(address) {
			return true
		}
	}
	return false
}

// ParseTrustedProxy parses a CIDR, e.g. 10.0.0.0/8, or a single IP address, e.g. 10.0.0.1.
func ParseTrustedProxy(value string) (netip.Prefix, error) {
	if strings.Contains(value, "/") {
		prefix, prefixError := netip.ParsePrefix(value)
		if prefixError != nil {
			return netip.Prefix{}, prefixError
		}
		return prefix.Masked(), nil
	}
	address, addressError := netip.ParseAddr(value)
	if addressError != nil {
		return netip.Prefix{}, addressError
	}
	address = address.Unmap()
	return netip.PrefixFrom(address, address.BitLen()), nil
}
