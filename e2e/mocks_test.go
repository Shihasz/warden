//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// requestLog records the requests a mock received, safely across the
// server's goroutines.
type requestLog struct {
	mu    sync.Mutex
	paths []string
}

func (l *requestLog) add(entry string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.paths = append(l.paths, entry)
}

func (l *requestLog) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.paths)
}

// ---------------------------------------------------------------- OSV

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvVuln struct {
	ID       string        `json:"id"`
	Summary  string        `json:"summary"`
	Aliases  []string      `json:"aliases,omitempty"`
	Severity []osvSeverity `json:"severity,omitempty"`
}

// mockOSV serves the two OSV endpoints warden uses: POST /v1/querybatch
// and GET /v1/vulns/{id}.
type mockOSV struct {
	t      *testing.T
	server *httptest.Server
	log    requestLog

	mu     sync.Mutex
	byPURL map[string][]string
	vulns  map[string]osvVuln
}

func newMockOSV(t *testing.T) *mockOSV {
	t.Helper()
	m := &mockOSV{t: t, byPURL: map[string][]string{}, vulns: map[string]osvVuln{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/querybatch", m.handleBatch)
	mux.HandleFunc("/v1/vulns/", m.handleVuln)
	m.server = httptest.NewServer(mux)
	t.Cleanup(m.server.Close)
	return m
}

// URL is the API root warden is pointed at via WARDEN_OSV_URL.
func (m *mockOSV) URL() string { return m.server.URL }

// AddVuln makes the mock report vulnerability id against the package
// identified by purl. cvss is a CVSS v3 vector (empty for a record with no
// severity data); aliases typically carries the CVE ID.
func (m *mockOSV) AddVuln(purl, id, cvss string, aliases ...string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v := osvVuln{ID: id, Summary: "mock vulnerability " + id, Aliases: aliases}
	if cvss != "" {
		v.Severity = []osvSeverity{{Type: "CVSS_V3", Score: cvss}}
	}
	m.vulns[id] = v
	m.byPURL[purl] = append(m.byPURL[purl], id)
}

func (m *mockOSV) handleBatch(w http.ResponseWriter, r *http.Request) {
	m.log.add(r.Method + " " + r.URL.Path)

	var req struct {
		Queries []struct {
			Package struct {
				PURL string `json:"purl"`
			} `json:"package"`
		} `json:"queries"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		m.t.Errorf("mock OSV: unreadable querybatch body: %v", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	type vulnRef struct {
		ID string `json:"id"`
	}
	type result struct {
		Vulns []vulnRef `json:"vulns,omitempty"`
	}
	resp := struct {
		Results []result `json:"results"`
	}{Results: make([]result, len(req.Queries))}

	m.mu.Lock()
	for i, q := range req.Queries {
		for _, id := range m.byPURL[q.Package.PURL] {
			resp.Results[i].Vulns = append(resp.Results[i].Vulns, vulnRef{ID: id})
		}
	}
	m.mu.Unlock()

	writeJSON(w, resp)
}

func (m *mockOSV) handleVuln(w http.ResponseWriter, r *http.Request) {
	m.log.add(r.Method + " " + r.URL.Path)

	id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
	m.mu.Lock()
	v, ok := m.vulns[id]
	m.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, v)
}

// ------------------------------------------------------------ deps.dev

// mockDepsDev serves GET /v3/systems/{system}/packages/{name}/versions/{version},
// where {name} is percent-encoded exactly as the real API requires.
// Versions with no registered licenses answer 404, like deps.dev does for
// packages it has no record of.
type mockDepsDev struct {
	t      *testing.T
	server *httptest.Server
	log    requestLog

	mu       sync.Mutex
	licenses map[string][]string
}

func newMockDepsDev(t *testing.T) *mockDepsDev {
	t.Helper()
	m := &mockDepsDev{t: t, licenses: map[string][]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/v3/systems/", m.handleVersion)
	m.server = httptest.NewServer(mux)
	t.Cleanup(m.server.Close)
	return m
}

// URL is the API root warden is pointed at via WARDEN_DEPSDEV_URL.
func (m *mockDepsDev) URL() string { return m.server.URL }

func depsKey(system, name, version string) string {
	return system + "/" + name + "@" + version
}

// Licenses registers the SPDX identifiers deps.dev reports for a version.
// system is deps.dev's lowercase system name: "go", "npm", or "pypi".
func (m *mockDepsDev) Licenses(system, name, version string, licenses ...string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.licenses[depsKey(system, name, version)] = licenses
}

func (m *mockDepsDev) handleVersion(w http.ResponseWriter, r *http.Request) {
	m.log.add(r.Method + " " + r.URL.EscapedPath())

	// {system}/packages/{name}/versions/{version}: split the *escaped*
	// path, because the name itself may contain an encoded "/".
	parts := strings.Split(strings.TrimPrefix(r.URL.EscapedPath(), "/v3/systems/"), "/")
	if len(parts) != 5 || parts[1] != "packages" || parts[3] != "versions" {
		m.t.Errorf("mock deps.dev: unexpected request path %q", r.URL.EscapedPath())
		http.NotFound(w, r)
		return
	}
	name, err := url.PathUnescape(parts[2])
	if err != nil {
		m.t.Errorf("mock deps.dev: bad package name escaping in %q: %v", r.URL.EscapedPath(), err)
		http.NotFound(w, r)
		return
	}
	version, err := url.PathUnescape(parts[4])
	if err != nil {
		m.t.Errorf("mock deps.dev: bad version escaping in %q: %v", r.URL.EscapedPath(), err)
		http.NotFound(w, r)
		return
	}

	m.mu.Lock()
	licenses, ok := m.licenses[depsKey(parts[0], name, version)]
	m.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, struct {
		Licenses []string `json:"licenses"`
	}{Licenses: licenses})
}

// ----------------------------------------------------------------- KEV

const kevFeedPath = "/known_exploited_vulnerabilities.json"

// filler is always present in the mock catalog: warden rejects an empty
// catalog (it would silently mark nothing as exploited), so a scenario
// that wants "nothing relevant is exploited" still needs one unrelated entry.
const kevFiller = "CVE-1999-0001"

// mockKEV serves a CISA-shaped KEV catalog.
type mockKEV struct {
	t      *testing.T
	server *httptest.Server
	log    requestLog

	mu   sync.Mutex
	cves []string
}

func newMockKEV(t *testing.T) *mockKEV {
	t.Helper()
	m := &mockKEV{t: t, cves: []string{kevFiller}}
	mux := http.NewServeMux()
	mux.HandleFunc(kevFeedPath, m.handle)
	m.server = httptest.NewServer(mux)
	t.Cleanup(m.server.Close)
	return m
}

// URL is the full catalog URL warden is pointed at via WARDEN_KEV_URL.
func (m *mockKEV) URL() string { return m.server.URL + kevFeedPath }

// SetExploited replaces the catalog's contents with the given CVE IDs
// (plus the always-present filler entry).
func (m *mockKEV) SetExploited(cves ...string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cves = append([]string{kevFiller}, cves...)
}

func (m *mockKEV) handle(w http.ResponseWriter, r *http.Request) {
	m.log.add(r.Method + " " + r.URL.Path)

	type entry struct {
		CVEID string `json:"cveID"`
	}
	m.mu.Lock()
	entries := make([]entry, len(m.cves))
	for i, id := range m.cves {
		entries[i] = entry{CVEID: id}
	}
	m.mu.Unlock()

	writeJSON(w, struct {
		Title           string  `json:"title"`
		CatalogVersion  string  `json:"catalogVersion"`
		Count           int     `json:"count"`
		Vulnerabilities []entry `json:"vulnerabilities"`
	}{
		Title:           "warden e2e mock catalog",
		CatalogVersion:  "e2e",
		Count:           len(entries),
		Vulnerabilities: entries,
	})
}
