package services

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// CustomClaims is the payload encoded in every access token issued by gAuth.
type CustomClaims struct {
	UserID   string            `json:"user_id"`
	Data     map[string]string `json:"data,omitempty"`
	Platform string            `json:"platform,omitempty"`
	jwt.RegisteredClaims
}

// TokenManager issues and verifies access tokens.
type TokenManager interface {
	Generate(userID string, platform string, data map[string]string) (string, error)
	Parse(tokenString string) (*CustomClaims, error)
}

type tokenManager struct {
	secret []byte
	ttl    time.Duration
}

// NewJWTManager builds a TokenManager that signs HS256 tokens with the given
// secret and makes them valid for the given ttl.
func NewJWTManager(secret string, ttl time.Duration) TokenManager {
	return &tokenManager{secret: []byte(secret), ttl: ttl}
}

func (m *tokenManager) Generate(userID string, platform string, data map[string]string) (string, error) {
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, CustomClaims{
		UserID:   userID,
		Data:     data,
		Platform: platform,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(m.ttl)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	})
	return token.SignedString(m.secret)
}

func (m *tokenManager) Parse(tokenString string) (*CustomClaims, error) {
	if tokenString == "" {
		return nil, ErrTokenRequired
	}
	claims := &CustomClaims{}
	token, err := jwt.ParseWithClaims(
		tokenString,
		claims,
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, ErrInvalidSigningMethod
			}
			return m.secret, nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
	)
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, ErrInvalidToken
	}
	return claims, nil
}

// StripBearer removes an optional "Bearer " prefix from an authorization
// header value.
func StripBearer(headerValue string) string {
	const prefix = "Bearer "
	if len(headerValue) > len(prefix) && headerValue[:len(prefix)] == prefix {
		return headerValue[len(prefix):]
	}
	return headerValue
}

var (
	ErrTokenRequired        = errors.New("authorization token is required")
	ErrInvalidToken         = errors.New("invalid token")
	ErrInvalidSigningMethod = errors.New("invalid token signing method")
)
