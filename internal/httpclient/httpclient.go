// Package httpclient builds the http.Client warden uses for every
// outbound request. The standard library's http.DefaultClient has no
// timeout at all, so a server that accepts a connection and then goes
// silent would hang the caller indefinitely.
package httpclient

import (
	"net/http"
	"time"
)

// DefaultTimeout bounds a single request end to end: connecting, sending,
// waiting for response headers, and reading the entire response body.
const DefaultTimeout = 30 * time.Second

// New returns an http.Client with DefaultTimeout applied.
func New() *http.Client {
	return &http.Client{Timeout: DefaultTimeout}
}
