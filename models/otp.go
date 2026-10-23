package models

import (
	"crypto/rand"
	"math/big"
)

type OTP struct {
	ID           uint   `gorm:"primaryKey,autoIncrement" json:"id"`
	UserID       string `json:"user_id"`
	Email        string `json:"email"`
	PhoneNumber  string `json:"phone_number"`
	Code         string `json:"code"`
	CodeExpireAt string `json:"code_expire_at"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
}

// GenerateOTP returns a cryptographically random six digit code. Leading
// digits avoid zero only because the charset starts at 1.
func (o *OTP) GenerateOTP() string {
	const (
		length     = 6
		charset    = "123456789"
		charsetLen = int64(len(charset))
	)

	code := make([]byte, length)
	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(charsetLen))
		if err != nil {
			// crypto/rand failing means the system entropy source is
			// broken; panic is safer than returning a predictable code.
			panic("crypto/rand failed: " + err.Error())
		}
		code[i] = charset[n.Int64()]
	}
	return string(code)
}
