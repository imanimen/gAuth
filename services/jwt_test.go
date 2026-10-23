package services

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testSecret = "unit-test-secret"

func NewTestTokenManager(ttl time.Duration) TokenManager {
	return NewJWTManager(testSecret, ttl)
}

func TestTokenGenerateParseRoundTrip(t *testing.T) {
	tm := NewTestTokenManager(10 * time.Minute)

	token, err := tm.Generate("user-1", "web", map[string]string{"session": "abc"})
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	claims, err := tm.Parse(token)
	require.NoError(t, err)
	assert.Equal(t, "user-1", claims.UserID)
	assert.Equal(t, "web", claims.Platform)
	assert.Equal(t, "abc", claims.Data["session"])
	assert.True(t, claims.ExpiresAt.After(time.Now()))
}

func TestGenerateWithoutData(t *testing.T) {
	tm := NewTestTokenManager(10 * time.Minute)

	token, err := tm.Generate("user-1", "ios", nil)
	require.NoError(t, err)

	claims, err := tm.Parse(token)
	require.NoError(t, err)
	assert.Equal(t, "ios", claims.Platform)
	assert.Nil(t, claims.Data)
}

func TestParseRejectsEmptyToken(t *testing.T) {
	tm := NewTestTokenManager(10 * time.Minute)

	_, err := tm.Parse("")
	assert.ErrorIs(t, err, ErrTokenRequired)
}

func TestParseRejectsTamperedToken(t *testing.T) {
	tm := NewTestTokenManager(10 * time.Minute)

	token, err := tm.Generate("user-1", "web", nil)
	require.NoError(t, err)

	_, err = tm.Parse(token + "x")
	assert.Error(t, err)
}

func TestParseRejectsWrongSecret(t *testing.T) {
	other := NewJWTManager("different-secret", 10*time.Minute)

	token, err := NewTestTokenManager(10*time.Minute).Generate("user-1", "web", nil)
	require.NoError(t, err)

	_, err = other.Parse(token)
	assert.Error(t, err)
}

func TestParseRejectsExpiredToken(t *testing.T) {
	tm := NewTestTokenManager(-10 * time.Minute)

	token, err := tm.Generate("user-1", "web", nil)
	require.NoError(t, err)

	_, err = tm.Parse(token)
	require.Error(t, err)
	assert.ErrorIs(t, err, jwt.ErrTokenExpired)
}

func TestParseRejectsNoneAlg(t *testing.T) {
	token := jwt.NewWithClaims(jwt.SigningMethodNone, CustomClaims{
		UserID: "user-1",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})
	signed, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)

	tm := NewTestTokenManager(10 * time.Minute)
	_, err = tm.Parse(signed)
	assert.Error(t, err)
}

func TestStripBearer(t *testing.T) {
	assert.Equal(t, "token", StripBearer("Bearer token"))
	assert.Equal(t, "Bearer", StripBearer("Bearer"))
	assert.Equal(t, "token", StripBearer("token"))
	assert.Equal(t, "", StripBearer(""))
}
