package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateOTPShape(t *testing.T) {
	otp := &OTP{}

	for i := 0; i < 200; i++ {
		code := otp.GenerateOTP()
		assert.Len(t, code, 6, "code should be six characters")
		for _, c := range code {
			assert.Contains(t, "123456789", string(c), "code must use digits 1-9 only")
		}
	}
}

func TestGenerateOTPVaries(t *testing.T) {
	otp := &OTP{}

	seen := make(map[string]bool)
	for i := 0; i < 50; i++ {
		seen[otp.GenerateOTP()] = true
	}
	// with 9^6 possibilities, 50 draws colliding exactly to one value is
	// practically impossible.
	assert.Greater(t, len(seen), 10)
}
