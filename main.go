package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

var (
	redirect string
)

func main() {
	logger := log.New(os.Stdout, "", log.Ldate|log.Ltime|log.Lshortfile)

	logger.Printf("foo")

	mux := http.NewServeMux()

	mux.Handle("/", &homeHandler{})
	mux.Handle("/authorize", &authorizeHandler{})
	mux.Handle("/token", &tokenHandler{})
	mux.Handle("/login", &loginHandler{})

	err := http.ListenAndServe(":8080", mux)
	if err != nil {
		return
	}
}

type homeHandler struct{}

func (h *homeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_, err := w.Write([]byte("Hello world!"))
	if err != nil {
		return
	}
}

type authorizeHandler struct{}

func (h *authorizeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	loginHtml := `<!doctype html>
		<html>
		<body>
		<h1>foo & bar</h1>
		<form method="POST" action="/login">
		<button type="submit">Login</button>
		</form>
		</body>
		</html>`
	log.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
	if r.Method == http.MethodGet {
		redirect = r.URL.Query().Get("redirect_uri")
		// http.ServeFile(w, r, "foo.html")
		bytes := []byte(loginHtml)
		_, err := w.Write(bytes)
		if err != nil {
			return
		}
	} else {
		NotFoundHandler(w, r)
	}
}

func InternalServerErrorHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte("500 Internal Server Error"))
}

func NotFoundHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte("404 Not Found"))
}

type loginHandler struct{}

func (h *loginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
	if r.Method == http.MethodPost {
		w.Header().Set("Location", redirect)
		w.WriteHeader(http.StatusFound)
	} else {
		NotFoundHandler(w, r)
	}
}

type tokenHandler struct{}

func (h *tokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
	if r.Method == http.MethodPost {
		for k, v := range r.Header {
			log.Printf("%v: %v\n", k, v)
		}

		if r.Body != nil {
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				fmt.Printf("Body reading error: %v", err)
				return
			}
			log.Printf("POST Body:\n%s\n", bodyBytes)
			defer r.Body.Close()
		}

		t := map[string]interface{}{
			"access_token": 1234,
		}

		bytes, err1 := json.Marshal(t)
		if err1 != nil {
			return
		}
		_, err2 := w.Write(bytes)
		if err2 != nil {
			return
		}
	} else {
		NotFoundHandler(w, r)
	}
}
