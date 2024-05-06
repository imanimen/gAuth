package providers

import (
	"net/mail"
	"regexp"
)



type IValidations interface {
	IsValidEmail(string) bool
	IsValidMobile(string) bool
	IsValidUsername(string) bool
}

type Validations struct {
	Email 			string `form:"email" binding:"required,email"`
	PhoneNumber  	string `form:"mobile" binding:"required"`
}

func (v Validations) IsValidEmail(email string) bool {
	
	if email == "" {
		return false
	}

	if len(email) < 3 {
		return false
	}

	_, err := mail.ParseAddress(email)
	if err != nil {
		return false
	}

	return true
}

func (v Validations) IsValidUsername(username string) bool {
	if username == "" {
		return false
	}

	if len(username) < 4 {
		return false
	}

	if len(username) > 16 {
		return false
	}

	match, _ := regexp.MatchString("^[A-Za-z][A-Za-z0-9_.]+$", username)
	return match
}

func (v Validations) IsValidMobile(phoneNumber string) bool {
	    //  for Iranian phone numbers
		iranRegex := `^(\+98|0)?9\d{9}$`
		re := regexp.MustCompile(iranRegex)
		
		return re.MatchString(phoneNumber)
}


func NewValidations() IValidations {
	return &Validations{}
}