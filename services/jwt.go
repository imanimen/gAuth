package services

import (
	"github.com/golang-jwt/jwt/v5"
	"os"
	"time"
)

// GenerateJWT generates a JWT token with the provided user ID and additional data.
// The token is signed using a secret key stored in the environment variable "SECRET".
// The token is valid for 10 minutes from the time of generation.
func GenerateJWT(userId string, data map[string]string) (string, error) {
	// Get the secret key from environment variable
	secret := []byte(os.Getenv("SECRET"))

	// Create a new JWT token
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userId,
		// Assuming 'data' contains key-value pairs for additional data
		"data": data,
		"exp":  time.Now().Local().Add(time.Minute * time.Duration(10)).Unix(),
		"nbf":  time.Now().Unix(),
	})

	// Sign the token with the secret key
	tokenString, err := jwtToken.SignedString(secret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// GetValueFromToken parses the provided JWT token string, verifies its signature using the
// "SECRET" environment variable, and extracts the value of the specified key from the
// "data" claim. If the token is invalid or the desired key is not found, an error is
// returned.
func GetValueFromToken(tokenString string, desiredKey string) (string, error) {
	// Parse the token

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("SECRET")), nil
	})

	if err != nil {
		return "", err
	}

	// Check if the token is valid
	if !token.Valid {
		return "", jwt.ErrSignatureInvalid
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		// Check if "data" claim exists and is a map[string]interface{}
		if dataClaim, exists := claims["data"].(map[string]interface{}); exists {
			if value, valueExists := dataClaim[desiredKey].(string); valueExists {
				return value, nil
			}
		}
	}

	//return "", jwt.ValidationError{Inner: err, Errors: jwt.ValidationErrorClaimsInvalid}
	return "", jwt.ErrTokenInvalidClaims
}
