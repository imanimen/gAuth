package middlewares

import (
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/imanimen/gAuth/models"
)

func AuthMiddleware(getUserByID func(id string) (*models.User, error)) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.Request.Header.Get("authorization")
		if strings.HasPrefix(tokenString, "Bearer ") {
			tokenString = strings.TrimPrefix(tokenString, "Bearer ")
		}
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("SECRET")), nil
		})
		if err != nil {
			respondWithError(c, 401, "authorization header required "+err.Error())
			return
		}

		if !token.Valid {
			respondWithError(c, 401, "invalid token")
			return
		}

		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			respondWithError(c, 401, "invalid token")
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok {

			user, err := getUserByID(claims["user_id"].(string))
			if err != nil {
				respondWithError(c, 401, "invalid token")
				return
			}
			c.AddParam("__user_id", user.ID)
			c.Next()
		} else {
			respondWithError(c, 401, "invalid token")
		}
	}
}

func respondWithError(c *gin.Context, code int, message interface{}) {
	c.AbortWithStatusJSON(code, gin.H{"error": message})
}
