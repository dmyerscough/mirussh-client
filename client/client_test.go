package client

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthentication(t *testing.T) {

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"token": "abc123"}`)
	}))
	defer ts.Close()

	token, _ := Authenticate(http.Client{}, ts.URL, "damian", "secret")

	if token != "abc123" {
		t.Errorf("Expected: abc123 got: %v", token)
	}

}

func TestAuthenticationError(t *testing.T) {

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, `{"error": "invalid username/password"}`)
	}))
	defer ts.Close()

	token, err := Authenticate(http.Client{}, ts.URL, "damian", "secret")

	if err == nil {
		t.Errorf("Expected error response")
	}

	if token != "" {
		t.Errorf("Expected: '' got: %v", token)
	}

}
