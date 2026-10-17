package osv

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Shihasz/warden/internal/sbom"
)

// newHungServer returns a server whose handler blocks until release is
// called. Blocking on an explicit channel, rather than r.Context().Done(),
// is deliberate: for a POST whose body the handler never reads, net/http
// doesn't watch the connection for a client disconnect, so the request
// context isn't cancelled when the client gives up, and server.Close()
// would wait out the handler's entire sleep.
func newHungServer() (server *httptest.Server, release func()) {
	done := make(chan struct{})
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-done
	}))
	return server, func() { close(done) }
}

func TestNewClient_DefaultHasTimeout(t *testing.T) {
	if NewClient().httpClient.Timeout <= 0 {
		t.Fatal("default OSV client has no timeout — requests to a silent server would hang forever")
	}
}

func TestScan_HungServerTimesOut(t *testing.T) {
	server, release := newHungServer()
	defer server.Close()
	defer release() // defers run last-in-first-out: this unblocks the handler before Close() waits on it

	client := NewClient(
		WithHTTPClient(&http.Client{Timeout: 100 * time.Millisecond}),
		WithQueryBatchURL(server.URL+"/querybatch"),
		WithVulnBaseURL(server.URL+"/vulns/"),
	)

	start := time.Now()
	_, _, err := client.Scan(context.Background(), []sbom.Component{
		{Name: "x", Version: "1.0.0", PURL: "pkg:pypi/x@1.0.0"},
	})
	if err == nil {
		t.Fatal("Scan() against a server that never responds should return an error, got nil")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("Scan() took %v to give up, want it bounded near the 100ms client timeout", elapsed)
	}
}
