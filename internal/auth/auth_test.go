package auth

import (
	"testing"
	"net/http"
)

func TestGetAPIKey(t *testing.T) {
	contentTypeHeader := http.Header{}
	contentTypeHeader.Add("Content-Type", "image/png")
	tests := []struct{
		name string
		input http.Header
		expectedOutput string
		expectedError error
	}{
		{
			name: "Empty header",
			input: http.Header{},
			expectedOutput: "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Header with no Auth Header",
			input: http.Header{
				"Content-Type": []string{"image/png"},
			},
			expectedOutput: "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Header with only Auth Header and malformed key",
			input: http.Header{
				"Authorization": []string{"Bearer abcde"},
			},
			expectedOutput: "",
			expectedError: ErrMalFormedKey,
		},
		{
			name: "Header with many headers and malformed key",
			input: http.Header{
				"Authorization": []string{"Bearer abcde"},
				"Content-Type": []string{"video/mp4"},
				"User-Agent": []string{"testing"},
			},
			expectedOutput: "",
			expectedError: ErrMalFormedKey,
		},
		{
			name: "Header with many headers",
			input: http.Header{
				"Authorization": []string{"ApiKey ABC"},
				"Content-Type": []string{"video/mp4"},
				"User-Agent": []string{"testing"},
			},
			expectedOutput: "ABC",
			expectedError: nil,
		},
		{
			name: "Header with only auth header",
			input: http.Header{
				"Authorization": []string{"ApiKey ABC"},
			},
			expectedOutput: "ABC",
			expectedError: nil,
		},
		
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := GetAPIKey(test.input)
			if err != test.expectedError {
				t.Errorf("expected: %v got :%v", test.expectedError, err)
			}

			if result != test.expectedOutput {
				t.Errorf("wanted: %v got: %v", test.expectedOutput, result)
			}
		})
	}
}
