package endpoints

import (
	"strings"
	"testing"
)

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestResolve_UnsetMeansDefaults(t *testing.T) {
	o, err := resolve(envOf(nil))
	if err != nil {
		t.Fatalf("resolve() error = %v", err)
	}
	if o.OSV != "" || o.DepsDev != "" || o.KEV != "" || len(o.Notices) != 0 {
		t.Errorf("resolve() with nothing set = %+v, want zero value", o)
	}
}

func TestResolve_AcceptsAndAnnounces(t *testing.T) {
	o, err := resolve(envOf(map[string]string{
		EnvOSV:     "http://127.0.0.1:8080/",
		EnvDepsDev: "https://mirror.example.com/deps/",
		EnvKEV:     "http://localhost:9000/kev.json",
	}))
	if err != nil {
		t.Fatalf("resolve() error = %v", err)
	}
	if o.OSV != "http://127.0.0.1:8080" {
		t.Errorf("OSV = %q, want trailing slash trimmed", o.OSV)
	}
	if o.DepsDev != "https://mirror.example.com/deps" {
		t.Errorf("DepsDev = %q, want trailing slash trimmed", o.DepsDev)
	}
	if o.KEV != "http://localhost:9000/kev.json" {
		t.Errorf("KEV = %q, want the URL unchanged", o.KEV)
	}
	if len(o.Notices) != 3 {
		t.Fatalf("got %d notices, want 3: %v", len(o.Notices), o.Notices)
	}
	for _, env := range []string{EnvOSV, EnvDepsDev, EnvKEV} {
		found := false
		for _, n := range o.Notices {
			found = found || strings.Contains(n, env)
		}
		if !found {
			t.Errorf("no notice mentions %s: %v", env, o.Notices)
		}
	}
}

func TestResolve_Rejects(t *testing.T) {
	cases := map[string]string{
		"plain http to a public host":    "http://example.com",
		"loopback lookalike hostname":    "http://localhost.evil.com",
		"loopback lookalike with suffix": "http://127.0.0.1.evil.com",
		"unspecified address":            "http://0.0.0.0:80",
		"non-http scheme":                "ftp://127.0.0.1/x",
		"file scheme":                    "file:///etc/passwd",
		"credentials in the URL":         "https://user:pass@example.com",
		"no host":                        "https://",
		"query string":                   "https://example.com/?a=b",
		"fragment":                       "https://example.com/#x",
		"not a URL":                      "not a url",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := resolve(envOf(map[string]string{EnvOSV: raw}))
			if err == nil {
				t.Fatalf("resolve(%q) should be rejected, got nil error", raw)
			}
			if !strings.Contains(err.Error(), EnvOSV) {
				t.Errorf("error = %q, want it to name %s", err.Error(), EnvOSV)
			}
			if strings.Contains(err.Error(), "pass@") {
				t.Errorf("error leaks credentials: %q", err.Error())
			}
		})
	}
}

func TestResolve_AllowsLoopbackForms(t *testing.T) {
	for _, raw := range []string{"http://127.0.0.1:1", "http://localhost:1", "http://[::1]:1", "https://example.com"} {
		if _, err := resolve(envOf(map[string]string{EnvDepsDev: raw})); err != nil {
			t.Errorf("resolve(%q) error = %v, want it accepted", raw, err)
		}
	}
}
