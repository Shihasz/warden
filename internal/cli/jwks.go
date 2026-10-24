package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/Shihasz/warden/internal/httpclient"
	"github.com/Shihasz/warden/internal/provenance/oidc"
)

// loadJWKS reads a JWKS from jwksFile when one is given (for offline or
// air-gapped verification), and otherwise fetches GitHub's published keys.
func loadJWKS(ctx context.Context, jwksFile string) (*oidc.JWKS, error) {
	if jwksFile != "" {
		data, err := os.ReadFile(jwksFile)
		if err != nil {
			return nil, fmt.Errorf("read JWKS file: %w", err)
		}
		return oidc.ParseJWKS(data)
	}
	return oidc.FetchJWKS(ctx, httpclient.New())
}
