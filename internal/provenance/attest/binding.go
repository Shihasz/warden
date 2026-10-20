package attest

import (
	"crypto/ed25519"

	"github.com/Shihasz/warden/internal/provenance/dsse"
)

// bindingAudiencePrefix namespaces warden's key-binding audiences, so a
// token minted for some other purpose can never be mistaken for one.
const bindingAudiencePrefix = "warden:ed25519:"

// OIDCTokenName and OIDCTokenMediaType identify the embedded GitHub
// Actions OIDC token among a statement's byproducts.
const (
	OIDCTokenName      = "github-actions-oidc-token"
	OIDCTokenMediaType = "application/jwt"
)

// BindingAudience returns the OIDC audience that binds pub to a GitHub
// Actions identity: the prefix plus the key's fingerprint.
//
// A signing run requests its OIDC token with this audience. GitHub signs
// the token, so a verifier who checks that signature learns that a
// workflow run in a specific repository asked for a token naming exactly
// this key. The only way to obtain such a token is to run a workflow in
// that repository, which is what ties an otherwise anonymous ephemeral
// key to a build identity.
func BindingAudience(pub ed25519.PublicKey) string {
	return bindingAudiencePrefix + dsse.KeyID(pub)
}
