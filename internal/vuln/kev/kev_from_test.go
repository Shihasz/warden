package kev

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestFetchAndCacheFrom(t *testing.T) {
	var hits int
	server := newFixtureServer(&hits)
	defer server.Close()

	c, err := FetchAndCacheFrom(context.Background(), server.URL, filepath.Join(t.TempDir(), "kev.json"), time.Hour, nil)
	if err != nil {
		t.Fatalf("FetchAndCacheFrom() error = %v", err)
	}
	if hits != 1 || !c.IsKnownExploited("CVE-2024-00001") {
		t.Errorf("hits = %d, known = %v; want one fetch from the given URL", hits, c.IsKnownExploited("CVE-2024-00001"))
	}
}
