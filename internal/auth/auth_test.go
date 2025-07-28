package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name:          "Valid Authorization Header",
			headers:       http.Header{"Authorization": []string{"ApiKey valid-api-key"}},
			expectedKey:   "valid-api-key",
			expectedError: nil,
		},
		{
			name:          "No Authorization Header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded, // Use the variable directly
		},
		{
			name:          "Malformed Authorization Header - Missing ApiKey Prefix",
			headers:       http.Header{"Authorization": []string{"Bearer token"}},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name:          "Malformed Authorization Header - No Key",
			headers:       http.Header{"Authorization": []string{"ApiKey"}},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiKey, err := GetAPIKey(tt.headers) // Use the function directly

			if apiKey != tt.expectedKey {
				t.Errorf("expected API key %q, got %q", tt.expectedKey, apiKey)
			}

			if (err == nil && tt.expectedError != nil) || (err != nil && tt.expectedError == nil) || (err != nil && tt.expectedError != nil && err.Error() != tt.expectedError.Error()) {
				t.Errorf("expected error %v, got %v", tt.expectedError, err)
			}
		})
	}
}
