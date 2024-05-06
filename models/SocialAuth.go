package models

type SocialAuth struct {
	ID             uint   `gorm:"primaryKey,autoIncrement" json:"id"`
	UserId         string `json:"user_id"`
	Provider       string `json:"provider"`
	ProviderUserID string `json:"provider_user_id"`
	CreatedAt      string `json:"string"`
}
