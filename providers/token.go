package providers

import "github.com/imanimen/gAuth/services"

// NewTokenManager builds the JWT TokenManager from the application config.
func NewTokenManager(config IConfig) services.TokenManager {
	return services.NewJWTManager(config.Secret(), config.TokenTTL())
}
