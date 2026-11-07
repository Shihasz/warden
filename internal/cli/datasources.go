package cli

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/spf13/cobra"

	"github.com/Shihasz/warden/internal/endpoints"
	"github.com/Shihasz/warden/internal/license/depsdev"
	"github.com/Shihasz/warden/internal/vuln/kev"
	"github.com/Shihasz/warden/internal/vuln/osv"
)

// dataSources holds the clients and feed URL warden uses to reach its
// external data sources, after applying any WARDEN_*_URL overrides.
type dataSources struct {
	osvClient     *osv.Client
	depsdevClient *depsdev.Client
	kevFeed       string
}

// newDataSources applies the endpoint overrides from the environment and
// announces each active one on stderr, so a redirected data source is
// never silent.
func newDataSources(cmd *cobra.Command) (*dataSources, error) {
	overrides, err := endpoints.FromEnv()
	if err != nil {
		return nil, err
	}
	warnf := stderrWarnf(cmd)
	for _, notice := range overrides.Notices {
		warnf("%s", notice)
	}

	ds := &dataSources{
		osvClient:     osv.NewClient(),
		depsdevClient: depsdev.NewClient(),
		kevFeed:       kev.FeedURL,
	}
	if overrides.OSV != "" {
		ds.osvClient = osv.NewClient(osv.WithBaseURL(overrides.OSV))
	}
	if overrides.DepsDev != "" {
		ds.depsdevClient = depsdev.NewClient(depsdev.WithBaseURL(overrides.DepsDev + "/v3"))
	}
	if overrides.KEV != "" {
		ds.kevFeed = overrides.KEV
	}
	return ds, nil
}

// kevCachePath returns the cache file to use with ds.kevFeed. A catalog
// from a non-default feed gets its own file, derived from the feed's URL,
// so a mock or mirror catalog can never be served later as if it were
// CISA's.
func (d *dataSources) kevCachePath(path string) string {
	if d.kevFeed == kev.FeedURL {
		return path
	}
	sum := sha256.Sum256([]byte(d.kevFeed))
	return path + "." + hex.EncodeToString(sum[:4])
}
