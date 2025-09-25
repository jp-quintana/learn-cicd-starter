package auth

import (
	"errors"
	"net/http"
	"reflect"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	// Define a slice of test cases, each with a name, a set of headers,
	// the expected API key, and the expected error.
	testCases := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name: "Valid API Key",
			headers: http.Header{
				"Authorization": []string{"ApiKey my-secret-api-key"},
			},
			expectedKey:   "my-secret-api-key",
			expectedError: nil,
		},
		{
			name:          "No Authorization Header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Authorization Header (no ApiKey)",
			headers: http.Header{
				"Authorization": []string{"Bearer my-token"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "Malformed Authorization Header (only ApiKey)",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
	}

	// Iterate through each test case and run the test.
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := GetAPIKey(tc.headers)

			// Check if the returned key matches the expected key.
			if key != tc.expectedKey {
				t.Errorf("expected key %q, but got %q", tc.expectedKey, key)
			}

			// Check if the returned error matches the expected error.
			// Using reflect.DeepEqual to handle both nil and non-nil errors correctly.
			if !reflect.DeepEqual(err, tc.expectedError) {
				t.Errorf("expected error %v, but got %v", tc.expectedError, err)
			}
		})
	}
}
