package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"gopkg.in/yaml.v3"
	"io"
	"log"
	"net/http"
	"os"
	"rsc.io/quote"
	"strings"
)

//go:embed resources/login.html
var loginHtml []byte

var (
	redirect string
)

type ResponseType string
type ClientType string

const (
	CODE               ResponseType = "code"
	TOKEN              ResponseType = "token"
	PASSWORD           ResponseType = "password"
	CLIENT_CREDENTIALS ResponseType = "client_credentials"
)

const (
	CONFIDENTIAL ClientType = "confidential"
	PUBLIC       ClientType = "public"
)

var responseTypeMap = map[string]ResponseType{
	"code":               CODE,
	"token":              TOKEN,
	"password":           PASSWORD,
	"client_credentials": CLIENT_CREDENTIALS,
}

func ParseString(str string) (ResponseType, bool) {
	c, ok := responseTypeMap[strings.ToLower(str)]
	return c, ok
}

type Client struct {
	Id         string     `yaml:"id"`
	Secret     string     `yaml:"secret"`
	ClientType ClientType `yaml:"type"`
}
type ConfigYaml struct {
	Port    int      `yaml:"port"`
	Clients []Client `yaml:"clients"`
}

func main() {
	logger := log.New(os.Stdout, "", log.Ldate|log.Ltime|log.Lshortfile)
	logger.Printf("%s", quote.Go())

	data, errf := os.ReadFile("config.yml")
	if errf != nil {
		log.Fatalf("unable to read file: %v", errf)
	}

	config := ConfigYaml{}

	erry := yaml.Unmarshal(data, &config)
	if erry != nil {
		log.Fatalf("error: %v", erry)
	}

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
	log.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
	if r.Method == http.MethodGet {
		responseTypeQueryParameter := r.URL.Query().Get("response_type")
		responseType, valid := ParseString(responseTypeQueryParameter)
		if !valid {
			InternalServerErrorHandler(w, r)
		}
		log.Printf("%s", responseType)
		redirect = r.URL.Query().Get("redirect_uri")

		// http.ServeFile(w, r, "foo.html")
		// bytes := []byte(loginHtml)
		_, err := w.Write(loginHtml)
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
