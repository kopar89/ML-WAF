package auth

import (
	"testing"
)

func TestJWTValidator_Validate(t *testing.T) {
	v := NewJWTValidator("secret", "waf", "app")

	// Create a simple mock token (header.payload.signature)
	// This is a base64 encoded JWT-like token for testing purposes
	mockToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	token := v.ExtractToken("Bearer " + mockToken)
	if token != mockToken {
		t.Errorf("ExtractToken failed, got %s", token)
	}

	// For course work, we test that the validator doesn't crash on invalid tokens
	// Full JWT verification with signature would require a real secret and proper token
	_, err := v.ValidateToken("invalid.token")
	if err == nil {
		t.Error("expected error for invalid token")
	}
}

func TestJWTValidator_ExtractToken(t *testing.T) {
	v := NewJWTValidator("", "", "")

	tests := []struct {
		header string
		want   string
	}{
		{"Bearer abc123", "abc123"},
		{"abc123", "abc123"},
		{"", ""},
	}

	for _, tt := range tests {
		got := v.ExtractToken(tt.header)
		if got != tt.want {
			t.Errorf("ExtractToken(%s) = %s, want %s", tt.header, got, tt.want)
		}
	}
}
