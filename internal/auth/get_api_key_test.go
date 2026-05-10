package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey test-key")

	apiKey, err := GetAPIKey(headers)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if apiKey != "test-key" {
		t.Fatalf("expected api key %q, got %q", "test-key", apiKey)
	}
}

func TestGetAPIKeyNoAuthorizationHeader(t *testing.T) {
	_, err := GetAPIKey(http.Header{})
	if err != ErrNoAuthHeaderIncluded {
		t.Fatalf("expected ErrNoAuthHeaderIncluded, got %v", err)
	}
}

func TestGetAPIKeyMalformedHeader(t *testing.T) {
	tests := []string{
		"Bearer test-key",
		"ApiKey",
		"test-key",
	}

	for _, authHeader := range tests {
		headers := http.Header{}
		headers.Set("Authorization", authHeader)

		_, err := GetAPIKey(headers)
		if err == nil {
			t.Fatalf("expected error for authorization header %q", authHeader)
		}
	}
}
