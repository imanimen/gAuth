package models

type Profile struct {
	ID        uint   `json:"id" gorm:"primaryKey"`
	UserId    string `json:"user_id"`
	Key       string `json:"key"`
	Value     string `json:"value"`
	UpdatedAt string `json:"updated_at"`
	CreatedAt string `json:"created_at"`
}

const KeyUsername = "username"
const KeyDisplayName = "display_name"
const KeyAvatar = "avatar"
const KeyCover = "cover"
const KeyAbout = "about"
const KeyFavoriteCategories = "favorite_categories"
const KeyFirstName = "first_name"
const KeyLastName = "last_name"
const KeyAge = "age"
const KeyBirthday = "birthdate"
const KeyGender = "gender"
