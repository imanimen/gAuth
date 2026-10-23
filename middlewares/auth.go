package middlewares

import (
	"github.com/gin-gonic/gin"
	"github.com/imanimen/gAuth/models"
	"github.com/imanimen/gAuth/services"
)

// Context keys used to propagate the authenticated user downstream.
const (
	CtxUserKey     = "auth_user"
	CtxPlatformKey = "auth_platform"
)

// GetUserByIDFunc is the callback used by the middleware to load the user
// identified by a token.
type GetUserByIDFunc func(id string) (*models.User, error)

// CurrentUser returns the user attached to the request by AuthMiddleware.
func CurrentUser(c *gin.Context) (models.User, error) {
	if value, ok := c.Get(CtxUserKey); ok {
		if user, ok := value.(models.User); ok {
			return user, nil
		}
	}
	return models.User{}, services.ErrInvalidToken
}

// CurrentPlatform returns the platform claim attached by AuthMiddleware.
func CurrentPlatform(c *gin.Context) string {
	if value, ok := c.Get(CtxPlatformKey); ok {
		if platform, ok := value.(string); ok {
			return platform
		}
	}
	return ""
}

// AuthMiddleware gates routes on a valid Bearer access token. On success it
// stores the user and platform claim on the request context for handlers.
func AuthMiddleware(getUserByID GetUserByIDFunc, tokenManager services.TokenManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, err := tokenManager.Parse(services.StripBearer(c.Request.Header.Get("Authorization")))
		if err != nil {
			c.AbortWithStatusJSON(401, gin.H{"error": err.Error()})
			return
		}

		user, err := getUserByID(claims.UserID)
		if err != nil {
			c.AbortWithStatusJSON(401, gin.H{"error": "invalid token"})
			return
		}

		c.Set(CtxUserKey, *user)
		c.Set(CtxPlatformKey, claims.Platform)
		c.Next()
	}
}
