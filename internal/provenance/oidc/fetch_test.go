package oidc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchToken(t *testing.T) {
	var gotAuth, gotQuery string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte(`{"count":1,"value":"fake.jwt.token"}`))
	}))
	defer server.Close()

	t.Setenv(EnvRequestURL, server.URL+"?api-version=2.0")
	t.Setenv(EnvRequestToken, "test-runtime-token")

	token, err := FetchToken(context.Background(), server.Client(), "https://example.com/aud")
	if err != nil {
		t.Fatalf("FetchToken() error = %v", err)
	}
	if token != "fake.jwt.token" {
		t.Errorf("token = %q, want fake.jwt.token", token)
	}
	if gotAuth != "bearer test-runtime-token" {
		t.Errorf("Authorization header = %q, want %q", gotAuth, "bearer test-runtime-token")
	}

	wantQuery := "api-version=2.0&audience=https%3A%2F%2Fexample.com%2Faud"
	if gotQuery != wantQuery {
		t.Errorf("request query = %q, want %q (existing api-version param should be preserved alongside audience)", gotQuery, wantQuery)
	}
}

func TestFetchToken_MissingEnvVars(t *testing.T) {
	t.Setenv(EnvRequestURL, "")
	t.Setenv(EnvRequestToken, "")

	if _, err := FetchToken(context.Background(), http.DefaultClient, "aud"); err == nil {
		t.Fatal("FetchToken() with missing env vars should return an error, got nil")
	}
}
