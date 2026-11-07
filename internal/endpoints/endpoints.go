// Package endpoints resolves optional overrides of the external data
// sources warden queries, read from environment variables. They exist so
// tests can point the real binary at local mock servers, and so an
// organization can use a private mirror.
//
// An override can redirect where vulnerability, license, and exploitation
// data comes from, so each one is validated strictly and announced
// whenever it is active.
package endpoints

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
)

// Environment variables that override a data source.
const (
	// EnvOSV is the root of an OSV-compatible API, e.g. http://127.0.0.1:8080.
	EnvOSV = "WARDEN_OSV_URL"
	// EnvDepsDev is the root of a deps.dev-compatible API.
	EnvDepsDev = "WARDEN_DEPSDEV_URL"
	// EnvKEV is the full URL of a CISA KEV catalog JSON document.
	EnvKEV = "WARDEN_KEV_URL"
)

// Overrides holds validated endpoint overrides. An empty field means the
// built-in default is used.
type Overrides struct {
	OSV     string
	DepsDev string
	KEV     string
	// Notices describes each active override, for the caller to show.
	Notices []string
}

// FromEnv reads and validates the overrides from the environment.
func FromEnv() (Overrides, error) {
	return resolve(os.Getenv)
}

func resolve(getenv func(string) string) (Overrides, error) {
	var o Overrides
	for _, spec := range []struct {
		env  string
		dst  *string
		root bool // API roots are normalized by trimming trailing slashes
	}{
		{EnvOSV, &o.OSV, true},
		{EnvDepsDev, &o.DepsDev, true},
		{EnvKEV, &o.KEV, false},
	} {
		raw := strings.TrimSpace(getenv(spec.env))
		if raw == "" {
			continue
		}
		value, err := validate(spec.env, raw)
		if err != nil {
			return Overrides{}, err
		}
		if spec.root {
			value = strings.TrimRight(value, "/")
		}
		*spec.dst = value
		o.Notices = append(o.Notices, fmt.Sprintf("%s is set: using %s instead of the default endpoint", spec.env, value))
	}
	return o, nil
}

func validate(env, raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%s: invalid URL: %w", env, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("%s: scheme must be http or https", env)
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("%s: URL has no host", env)
	}
	if u.User != nil {
		return "", fmt.Errorf("%s: URL must not contain credentials", env)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("%s: URL must not contain a query string or fragment", env)
	}
	if u.Scheme == "http" && !isLoopback(u.Hostname()) {
		return "", fmt.Errorf("%s: plain http is only allowed for localhost; use https", env)
	}
	return raw, nil
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
