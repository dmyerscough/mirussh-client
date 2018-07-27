package client

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

var AuthTests = []struct {
	httpStatus    int
	httpResponse  string
	expectedURL   string
	expectedToken string
}{
	{httpStatus: http.StatusOK, httpResponse: `{"token": "abc123"}`, expectedURL: "/auth/", expectedToken: "abc123"},
	{httpStatus: http.StatusBadRequest, httpResponse: `{"error": "invalid username/password"}`, expectedURL: "/auth/", expectedToken: ""},
}

func TestAuthentication(t *testing.T) {

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
