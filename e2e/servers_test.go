//go:build e2e

package e2e

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// failingServer answers every request with the given error status.
func failingServer(t *testing.T, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "simulated outage", status)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// hangingServer accepts requests and never answers them until the test
// ends. It blocks on an explicit channel and not on the request context:
// for a POST whose body is never read, net/http doesn't notice the client
// giving up, so the context would never be cancelled.
func hangingServer(t *testing.T) *httptest.Server {
	t.Helper()
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	t.Cleanup(func() {
		close(release) // cleanups run last-in-first-out: unblock handlers before Close waits on them
		srv.Close()
	})
	return srv
}

// bodyServer answers every request with 200 and the given body, whatever
// the request was.
func bodyServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}
