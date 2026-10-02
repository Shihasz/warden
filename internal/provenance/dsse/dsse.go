// Package dsse implements the Dead Simple Signing Envelope (DSSE) format
// (https://github.com/secure-systems-lab/dsse), used to sign an in-toto
// Statement.
package dsse

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strconv"
)

// Envelope is a DSSE envelope: a payload, its type, and one or more
// signatures over the Pre-Authentication Encoding (PAE) of both.
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"` // base64-encoded (standard encoding)
	Signatures  []Signature `json:"signatures"`
}

// Signature is one signature within a DSSE envelope. KeyID is an
// unauthenticated hint, per spec — it's not itself covered by the
// signature, so a verifier must independently decide which key to check
// against rather than trusting KeyID blindly.
type Signature struct {
	Sig   string `json:"sig"` // base64-encoded
	KeyID string `json:"keyid,omitempty"`
}

// PAE computes the DSSE Pre-Authentication Encoding of payloadType and
// payload, per
// https://github.com/secure-systems-lab/dsse/blob/v1.0.0/protocol.md:
//
//	PAE(type, body) = "DSSEv1" + SP + LEN(type) + SP + type + SP + LEN(body) + SP + body
//
// This is the exact byte sequence that gets signed — never the raw
// payload alone. Binding both the payload type and its byte length into
// the signed bytes is what prevents a type-confusion attack, where bytes
// legitimately signed under one payload type are replayed and
// misinterpreted as a different, structurally-compatible type.
func PAE(payloadType string, payload []byte) []byte {
	var out []byte
	out = append(out, "DSSEv1 "...)
	out = append(out, strconv.Itoa(len(payloadType))...)
	out = append(out, ' ')
	out = append(out, payloadType...)
	out = append(out, ' ')
	out = append(out, strconv.Itoa(len(payload))...)
	out = append(out, ' ')
	out = append(out, payload...)
	return out
}

// Sign builds and signs a DSSE envelope over payload, using priv (an
// ed25519 private key) and recording keyID as the signature's
// (unauthenticated) key hint.
func Sign(payloadType string, payload []byte, priv ed25519.PrivateKey, keyID string) (*Envelope, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid ed25519 private key size: got %d bytes, want %d", len(priv), ed25519.PrivateKeySize)
	}

	sig := ed25519.Sign(priv, PAE(payloadType, payload))

	return &Envelope{
		PayloadType: payloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures: []Signature{
			{Sig: base64.StdEncoding.EncodeToString(sig), KeyID: keyID},
		},
	}, nil
}

// Verify checks that env contains at least one valid signature over its
// payload from pub (an ed25519 public key), and returns the decoded
// payload only if a valid signature is found.
func Verify(env *Envelope, pub ed25519.PublicKey) ([]byte, error) {
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("decode envelope payload: %w", err)
	}
	if len(env.Signatures) == 0 {
		return nil, fmt.Errorf("envelope has no signatures")
	}

	pae := PAE(env.PayloadType, payload)

	for _, sig := range env.Signatures {
		sigBytes, err := base64.StdEncoding.DecodeString(sig.Sig)
		if err != nil {
			continue
		}
		if ed25519.Verify(pub, pae, sigBytes) {
			return payload, nil
		}
	}

	return nil, fmt.Errorf("no valid signature found for the given public key")
}
