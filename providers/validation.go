package providers

import (
	"net/mail"
	"regexp"
)

// IValidations offers request payload validation helpers.
type IValidations interface {
	IsValidEmail(string) bool
	IsValidMobile(string) bool
	IsValidUsername(string) bool
}

type Validations struct {
	usernamePattern *regexp.Regexp
	mobilePattern   *regexp.Regexp
}

// NewValidations builds the default validation set.
func NewValidations() IValidations {
	return &Validations{
		usernamePattern: regexp.MustCompile("^[A-Za-z][A-Za-z0-9_.]+$"),
		// Iranian mobile numbers.
		mobilePattern: regexp.MustCompile(`^(\+98|0)?9\d{9}$`),
	}
}

// IsValidEmail reports whether the address satisfies the simplest standard
// RFC 5322 shape.
func (v Validations) IsValidEmail(email string) bool {
	if len(email) < 3 {
		return false
	}
	_, err := mail.ParseAddress(email)
	return err == nil
}

// IsValidUsername reports whether the username is 4..16 chars long, starts
// with a letter and contains only letters, numbers, underscores and dots.
func (v Validations) IsValidUsername(username string) bool {
	if len(username) < 4 || len(username) > 16 {
		return false
	}
	return v.usernamePattern.MatchString(username)
}

// IsValidMobile reports whether the value matches the supported mobile
// number format.
func (v Validations) IsValidMobile(phoneNumber string) bool {
	return v.mobilePattern.MatchString(phoneNumber)
}
