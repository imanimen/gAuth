package models

import (
	"git.dyneemadev.com/micro-services/go-auth/utils"
)

type User struct {
	ID               string `json:"id" gorm:"primaryKey"`
	Username         string `json:"username"`
	Email            string `json:"email"`
	PhoneNumber      string `json:"phone_number"`
	RegistrationStep int    `json:"step"`
	EmailVerifiedAt  string `json:"email_verified_at"`
	CreatedAt        string `json:"created_at"`
	UpdatedAt        string `json:"updated_at"`
	// appendable fields
	// ADDED gorm:"-"` to exclude migration of the field
	Avatar             string `json:"avatar" gorm:"-"`
	Cover              string `json:"cover" gorm:"-"`
	DisplayName        string `json:"display_name" gorm:"-"`
	FirstName          string `json:"first_name" gorm:"-"`
	LastName           string `json:"last_name" gorm:"-"`
	Birthdate          string `json:"birthdate" gorm:"-"`
	Age                string `json:"age" gorm:"-"`
	About              string `json:"about" gorm:"-"`
	Gender             string `json:"gender" gorm:"-"`
	FavoriteCategories string `json:"favorite_categories" gorm:"-"`
}

const FirstStep = 1  // otp sent
const SecondStep = 2 // verified otp
const ThirdStep = 3  // update profile
const FourthStep = 4 // update categories

// GetAvatar retrieves the avatar URL for the user from the file service.
// It first checks if the user has an avatar value set, and if so, calls
// the getFilePath function to retrieve the file URL, caching it forever.
// If there is any error getting the file path or the user has no avatar
// set, it returns an empty string.
func (u *User) GetAvatar(value string) string {
	if value != "" {
		avatar, err := utils.GetFilePath(value)
		if err != nil {
			return ""
		}
		return avatar
	}
	return ""
}

// GetCover returns the cover image file path for the user.
// It first checks if the user has a non-empty cover value,
// and if so calls getFilePath to retrieve the file path,
// returning it if found or an empty string if getFilePath returns an error.
// If the user has no cover value, it returns an empty string.
func (u *User) GetCover(value string) string {
	if value != "" {
		cover, err := utils.GetFilePath(value)
		if err != nil {
			return ""
		}
		return cover
	}
	return ""
}
