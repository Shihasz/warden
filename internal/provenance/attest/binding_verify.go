package attest

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/Shihasz/warden/internal/provenance/oidc"
)

// ErrNoOIDCToken means a statement carries no embedded GitHub OIDC token.
// Its signature can still be valid, but nothing ties the signing key to a
// build identity: anyone can sign a statement claiming any repository.
var ErrNoOIDCToken = errors.New("statement has no embedded GitHub OIDC token, so its claimed build identity is self-asserted and proves nothing about who built the artifact")

// oidcToken extracts the embedded token. found reports whether any token
// entry exists at all; err reports a malformed one.
func (s *Statement) oidcToken() (token string, found bool, err error) {
	var tokens []ResourceDescriptor
	for _, bp := range s.Predicate.RunDetails.Byproducts {
		if bp.Name == OIDCTokenName {
			tokens = append(tokens, bp)
		}
	}

	switch len(tokens) {
	case 0:
		return "", false, nil
	case 1:
		if len(tokens[0].Content) == 0 {
			return "", true, fmt.Errorf("embedded OIDC token is empty")
		}
		return string(tokens[0].Content), true, nil
	default:
		return "", true, fmt.Errorf("statement embeds %d OIDC tokens, want exactly 1", len(tokens))
	}
}

// HasOIDCToken reports whether the statement embeds a GitHub OIDC token.
func (s *Statement) HasOIDCToken() bool {
	_, found, _ := s.oidcToken()
	return found
}

// VerifyBinding proves that signer, the key that signed this statement's
// envelope, belongs to a GitHub Actions run whose identity matches the
// statement. It checks that:
//
//  1. the embedded token carries a valid GitHub signature (against jwks)
//     and a GitHub issuer;
//  2. the token's audience names signer, so GitHub vouched for exactly
//     this key; and
//  3. every identity claim in the statement equals what GitHub signed.
//
// The token's expiry is deliberately not enforced: the token is a
// historical record, not a bearer credential, and its audience binds it
// to one specific key, so replaying an old token gains an attacker
// nothing. This does mean verification needs GitHub to still publish the
// key that signed the token, and there is no transparency-log timestamp
// to pin when that happened; these are warden's documented limits
// compared to full Sigstore.
//
// It returns the token's claims, which are authoritative where the
// statement's own claims are not.
func (s *Statement) VerifyBinding(signer ed25519.PublicKey, jwks *oidc.JWKS) (*oidc.Claims, error) {
	token, found, err := s.oidcToken()
	if !found {
		return nil, ErrNoOIDCToken
	}
	if err != nil {
		return nil, err
	}

	claims, err := oidc.Verify(token, jwks, oidc.VerifyOptions{
		ExpectedAudience: BindingAudience(signer),
		AllowExpired:     true,
	})
	if err != nil {
		return nil, fmt.Errorf("verify embedded OIDC token: %w", err)
	}

	if err := s.checkClaimsMatch(claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// checkClaimsMatch requires the statement's identity fields to equal
// what GitHub's token implies, in both directions: a differing value and
// an extra, unbacked entry are both rejections.
func (s *Statement) checkClaimsMatch(claims *oidc.Claims) error {
	wantDef, wantBuilder, wantInvocation := identityFromClaims(claims)
	gotDef := s.Predicate.BuildDefinition

	var problems []string
	problems = append(problems, compareMaps("externalParameters", gotDef.ExternalParameters, wantDef.ExternalParameters)...)
	problems = append(problems, compareMaps("internalParameters", gotDef.InternalParameters, wantDef.InternalParameters)...)

	if len(gotDef.ResolvedDependencies) != len(wantDef.ResolvedDependencies) {
		problems = append(problems, fmt.Sprintf("resolvedDependencies: statement lists %d entries, GitHub's token implies %d",
			len(gotDef.ResolvedDependencies), len(wantDef.ResolvedDependencies)))
	} else {
		for i, want := range wantDef.ResolvedDependencies {
			got := gotDef.ResolvedDependencies[i]
			if got.URI != want.URI {
				problems = append(problems, fmt.Sprintf("resolvedDependencies[%d].uri: statement says %q, GitHub's token says %q", i, got.URI, want.URI))
			}
			problems = append(problems, compareMaps(fmt.Sprintf("resolvedDependencies[%d].digest", i), got.Digest, want.Digest)...)
		}
	}

	if got := s.Predicate.RunDetails.Builder.ID; got != wantBuilder.ID {
		problems = append(problems, fmt.Sprintf("builder.id: statement says %q, GitHub's token says %q", got, wantBuilder.ID))
	}
	if got := s.Predicate.RunDetails.Metadata.InvocationID; got != wantInvocation {
		problems = append(problems, fmt.Sprintf("metadata.invocationId: statement says %q, GitHub's token says %q", got, wantInvocation))
	}

	if len(problems) > 0 {
		return fmt.Errorf("statement disagrees with the GitHub-signed token:\n  - %s", strings.Join(problems, "\n  - "))
	}
	return nil
}

func compareMaps(name string, got, want map[string]string) []string {
	var problems []string
	for _, k := range slices.Sorted(maps.Keys(want)) {
		if g, ok := got[k]; !ok || g != want[k] {
			problems = append(problems, fmt.Sprintf("%s.%s: statement says %q, GitHub's token says %q", name, k, g, want[k]))
		}
	}
	for _, k := range slices.Sorted(maps.Keys(got)) {
		if _, ok := want[k]; !ok {
			problems = append(problems, fmt.Sprintf("%s.%s: unexpected extra entry not backed by GitHub's token", name, k))
		}
	}
	return problems
}
