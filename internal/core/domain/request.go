package domain

import (
	"io"
	"net/http"
)

// Headers set by this layer
const (
	REQUEST_ID_HEADER string = "X-REQUEST-ID"
	USER_INFO_HEADER  string = "X-USER-INFO"
	TOKEN_USE_HEADER  string = "X-TOKEN-USE"
)

const (
	HTTP_GET     string = "GET"
	HTTP_POST    string = "POST"
	HTTP_PUT     string = "PUT"
	HTTP_PATCH   string = "PATCH"
	HTTP_OPTIONS string = "OPTIONS"
	HTTP_HEAD    string = "HEAD"
	HTTP_DELETE  string = "DELETE"
)

// Request representation to be evaluated or executed by proxy
type Request struct {
	// The resource scheme
	Scheme string
	// The resource host
	Host string
	// The resource path
	Path string
	// Query string parameters
	Query string
	// HTTP Body reader
	Body io.ReadCloser
	// HTTP Method
	Method string
	// The resource Headers map
	Headers http.Header
}

// Proxy configured and ready to serve a response
type Proxy interface {
	ServeHTTP(rw http.ResponseWriter, req *http.Request)
}
