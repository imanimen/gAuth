package providers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsValidEmail(t *testing.T) {
	v := NewValidations()

	tests := []struct {
		name  string
		email string
		want  bool
	}{
		{"valid simple", "user@example.com", true},
		{"valid with dot domain", "first.last@sub.example.co", true},
		{"valid plus addressing", "user+tag@example.com", true},
		{"empty", "", false},
		{"too short", "a@", false},
		{"missing at", "userexample.com", false},
		{"missing domain", "user@", false},
		// RFC 5322 allows single-label domains, which net/mail accepts.
		{"single label domain", "user@domain", true},
		{"spaces", "user name@example.com", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, v.IsValidEmail(tc.email))
		})
	}
}

func TestIsValidUsername(t *testing.T) {
	v := NewValidations()

	tests := []struct {
		name     string
		username string
		want     bool
	}{
		{"valid minimal", "abcd", true},
		{"valid with digits", "abcd1234", true},
		{"valid underscore dot", "ab_c.d", true},
		{"valid 16 chars", "abcdefghijklmnop", true},
		{"empty", "", false},
		{"too short", "abc", false},
		{"too long", "abcdefghijklmnopq", false},
		{"starts with digit", "1abcd", false},
		{"starts with underscore", "_abcd", false},
		{"contains hyphen", "abcd-ef", false},
		{"contains space", "abcd ef", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, v.IsValidUsername(tc.username))
		})
	}
}

func TestIsValidUsernameLengthBoundary(t *testing.T) {
	v := NewValidations()

	assert.True(t, v.IsValidUsername("abcdefghijklmno"))    // 15
	assert.True(t, v.IsValidUsername("abcdefghijklmnop"))   // 16
	assert.False(t, v.IsValidUsername("abcdefghijklmnopq")) // 17
}

func TestIsValidMobile(t *testing.T) {
	v := NewValidations()

	tests := []struct {
		name   string
		mobile string
		want   bool
	}{
		{"local format", "09121234567", true},
		{"zero prefix", "091212345678", false},
		{"international", "+989121234567", true},
		{"missing leading 9", "0912123456", false},
		{"too short", "0912123456", false},
		{"letters", "091212345ab", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, v.IsValidMobile(tc.mobile))
		})
	}
}
