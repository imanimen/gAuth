package providers

import "github.com/imanimen/gAuth/services"

// NewOAuth builds the Google OAuth settings from the environment. Empty
// values fall back to the real Google endpoints.
func NewOAuth(config IConfig) *services.OAuthSettings {
	return services.NewGoogleOAuthSettings(
		config.Get("GOOGLE_CLIENT_ID"),
		config.Get("GOOGLE_CLIENT_SECRET"),
		config.Get("GOOGLE_REDIRECT_URL"),
		config.Get("GOOGLE_AUTH_URL"),
		config.Get("GOOGLE_TOKEN_URL"),
		config.Get("GOOGLE_USERINFO_URL"),
	)
}
