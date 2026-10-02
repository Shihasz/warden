package dsse

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"
)

// independentPAE reconstructs the expected PAE bytes using a different
// code path (fmt.Sprintf-based string building) than PAE's own
// byte-append implementation, so this test can't pass merely because
// both pieces of code share the same bug.
func independentPAE(t *testing.T, payloadType string, payload []byte) []byte {
	t.Helper()
	s := fmt.Sprintf("DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(payload), payload)
	return []byte(s)
}

func TestPAE(t *testing.T) {
	cases := []struct {
		payloadType string
		payload     []byte
	}{
		{"application/example", []byte("hello world")},
		{"application/vnd.in-toto+json", []byte(`{"a":1}`)},
		{"text/plain", []byte("")}, // empty payload
	}

	for _, tc := range cases {
		got := PAE(tc.payloadType, tc.payload)
		want := independentPAE(t, tc.payloadType, tc.payload)
		if string(got) != string(want) {
			t.Errorf("PAE(%q, %q) = %q, want %q", tc.payloadType, tc.payload, got, want)
		}
	}
}

func TestPAE_DiffersByPayloadType(t *testing.T) {
	payload := []byte("same payload bytes")
	a := PAE("application/type-a", payload)
	b := PAE("application/type-b", payload)
	if string(a) == string(b) {
		t.Error("PAE with different payload types produced identical bytes — this would allow a type-confusion attack")
	}
}

func TestSignAndVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	payload := []byte(`{"_type":"https://in-toto.io/Statement/v1"}`)
	env, err := Sign("application/vnd.in-toto+json", payload, priv, "test-key")
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	got, err := Verify(env, pub)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("Verify() returned payload %q, want %q", got, payload)
	}
}

func TestVerify_TamperedPayloadFails(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	env, err := Sign("application/vnd.in-toto+json", []byte(`{"amount":10}`), priv, "test-key")
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	env.Payload = base64.StdEncoding.EncodeToString([]byte(`{"amount":1000000}`))

	if _, err := Verify(env, pub); err == nil {
		t.Fatal("Verify() with a tampered payload should fail, got nil error")
	}
}

func TestVerify_WrongKeyFails(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	wrongPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	env, err := Sign("application/vnd.in-toto+json", []byte(`{}`), priv, "test-key")
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if _, err := Verify(env, wrongPub); err == nil {
		t.Fatal("Verify() with the wrong public key should fail, got nil error")
	}
}
