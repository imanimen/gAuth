package models

type User struct {
	ID               string `json:"id" gorm:"primaryKey"`
	Username         string `json:"username"`
	Email            string `json:"email"`
	PhoneNumber      string `json:"phone_number"`
	RegistrationStep int    `json:"step"`
	EmailVerifiedAt  string `json:"email_verified_at"`
	CreatedAt        string `json:"created_at"`
	UpdatedAt        string `json:"updated_at"`

	// Appendable fields resolved from the profiles table. The `gorm:"-"`
	// tag excludes them from migration.
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

const (
	FirstStep  = 1 // otp sent
	SecondStep = 2 // verified otp
	ThirdStep  = 3 // update profile
	FourthStep = 4 // update categories
)
