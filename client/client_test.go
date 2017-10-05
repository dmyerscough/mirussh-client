package client

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthentication(t *testing.T) {
	var AuthTests = []struct {
		httpStatus    int
		httpResponse  string
		expectedURL   string
		expectedToken string
	}{
		{httpStatus: http.StatusOK, httpResponse: `{"token": "abc123"}`, expectedURL: "/auth/", expectedToken: "abc123"},
		{httpStatus: http.StatusBadRequest, httpResponse: `{"error": "invalid username/password"}`, expectedURL: "/auth/", expectedToken: ""},
	}

	for _, test := range AuthTests {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(test.httpStatus)
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, test.httpResponse)

			if r.Method != "POST" {
				t.Errorf("Expected: POST Got: %q", r.Method)
			}

			if r.URL.EscapedPath() != test.expectedURL {
				t.Errorf("Expected: %q Got: %q", test.expectedURL, r.URL.EscapedPath())
			}

		}))
		defer ts.Close()

		token, _ := Authenticate(http.Client{}, ts.URL, "damian", "secret")

		if token != test.expectedToken {
			t.Errorf("Expected: %q Got: %q", test.expectedToken, token)
		}
	}
}

func TestSignCertificate(t *testing.T) {
	var CertificateSigningTests = []struct {
		httpStatus       int
		httpResponse     string
		expectedURL      string
		expectedResponse SingedAuthResponse
	}{
		{httpStatus: http.StatusOK, httpResponse: `{"username": "damian", "ttl": 300, "certificate": "aabbccddeeff"}`, expectedURL: "/management/sign/", expectedResponse: SingedAuthResponse{"damian", "aabbccddeeff", 300}},
	}

	for _, test := range CertificateSigningTests {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(test.httpStatus)
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, test.httpResponse)

			if r.Method != "POST" {
				t.Errorf("Expected: POST Got: %q", r.Method)
			}

			if r.URL.EscapedPath() != test.expectedURL {
				t.Errorf("Expected: %q Got: %q", test.expectedURL, r.URL.EscapedPath())
			}

			if r.Header.Get("X-Mirussh-Otp") != "123456" {
				t.Errorf("Expected: 123456 Got: %q", r.Header.Get("X-Mirussh-Otp"))
			}
		}))
		defer ts.Close()

		cert := SignCertificate(http.Client{}, ts.URL, "aabbccddeeff", "123456", "ssh-rsa AAAA")

		if cert.Username != test.expectedResponse.Username {
			t.Errorf("Expected: %q Got: %q", test.expectedResponse.Username, cert.Username)
		}

		if cert.Certificate != test.expectedResponse.Certificate {
			t.Errorf("Expected: %q Got: %q", test.expectedResponse.Certificate, cert.Certificate)
		}

		if cert.Ttl != test.expectedResponse.Ttl {
			t.Errorf("Expected: %q Got: %q", test.expectedResponse.Ttl, cert.Ttl)
		}

	}
}
