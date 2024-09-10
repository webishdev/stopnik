package http

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type CompressionMethod string

const (
	CompressionMethodGZip CompressionMethod = "gzip"
)

var supportedEncodingMethods = []CompressionMethod{CompressionMethodGZip}

type RequestData struct {
	scheme     string
	host       string
	path       string
	query      string
	fragment   string
	compressed *CompressionMethod
}

func NewRequestData(r *http.Request) *RequestData {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}

	host := r.Host
	path := r.URL.RawPath

	query := ""
	if r.URL.RawQuery != "" {
		query = "?" + r.URL.RawQuery
	}
	fragment := ""
	if r.URL.RawFragment != "" {
		fragment = "#" + r.URL.RawFragment
	}

	acceptEncodingHeader := r.Header.Get(AcceptEncoding)
	acceptEncoding := strings.Split(acceptEncodingHeader, ", ")

	var compress CompressionMethod
	for _, encoding := range acceptEncoding {
		for _, supported := range supportedEncodingMethods {
			if encoding == string(supported) {
				compress = supported
				break
			}
		}
	}

	return &RequestData{
		scheme:     scheme,
		host:       host,
		path:       path,
		query:      query,
		fragment:   fragment,
		compressed: &compress,
	}
}

func (r *RequestData) IssuerString() string {
	return fmt.Sprintf("%s://%s", r.scheme, r.host)
}

func (r *RequestData) URL() (*url.URL, error) {
	uri := fmt.Sprintf("%s://%s%s%s%s", r.scheme, r.host, r.path, r.query, r.fragment)

	return url.Parse(uri)
}

func (r *RequestData) Valid() bool {
	return r.host != "" && r.scheme != ""
}

func (r *RequestData) AcceptCompressed() (*CompressionMethod, bool) {
	return r.compressed, r.compressed != nil && *r.compressed != ""
}
