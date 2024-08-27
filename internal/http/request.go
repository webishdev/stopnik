package http

import (
	"fmt"
	"net/http"
	"net/url"
)

type RequestData struct {
	Scheme   string
	Host     string
	Path     string
	Query    string
	Fragment string
}

func NewRequestData(r *http.Request) *RequestData {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}

	query := ""
	if r.URL.RawQuery != "" {
		query = "?" + r.URL.RawQuery
	}
	fragment := ""
	if r.URL.RawFragment != "" {
		fragment = "#" + r.URL.RawFragment
	}
	return &RequestData{
		Scheme:   scheme,
		Host:     r.Host,
		Path:     r.URL.RawPath,
		Query:    query,
		Fragment: fragment,
	}
}

func (r *RequestData) IssuerString() string {
	return fmt.Sprintf("%s://%s", r.Scheme, r.Host)
}

func (r *RequestData) URL() (*url.URL, error) {
	uri := fmt.Sprintf("%s://%s%s%s%s", r.Scheme, r.Host, r.Path, r.Query, r.Fragment)

	return url.Parse(uri)
}
