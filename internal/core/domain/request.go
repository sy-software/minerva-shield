package domain

import "net/http"

// Headers set by this layer
const (
	REQUEST_ID_HEADER string = "X-REQUEST-ID"
)

// Request representation to be evaluated or executed by proxy
type Request struct {
	// The resource scheme
	Scheme string
	// The resource host
	Host string
	// The resource path
	Path string
	// The resource Headers map
	Headers http.Header
}
