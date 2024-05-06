package services

import (
	"bytes"
	"context"
	"encoding/json"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"io"
	"log"
	"net/http"
)

// Call makes an HTTP request to the specified URL using the provided method and payload.
// It returns the response as a map[string]interface{} and any error that occurred during the request.
// The request is made with a JSON content type.
func Call(url string, method string, payload []byte) (map[string]interface{}, error) {
	client := &http.Client{}
	req, err := http.NewRequest(method, url, bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Fatal("Error in request: ", err.Error())
		}
	}(resp.Body)

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// oAuth implementation
var (
	GoogleOAuthConfig = &oauth2.Config{
		ClientID:     "186417833863-scjsm0d18jt1s9jgvsntq8sgkm52v1s6.apps.googleusercontent.com",
		ClientSecret: "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",
		Endpoint:     google.Endpoint,
		RedirectURL:  "http://localhost:8080/auth/callback",
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
			"https://www.googleapis.com/auth/photoslibrary.readonly",
		},
	}
	OauthStateString = "random"
)

// OAuthGoogleUserInfo represents the user information returned from the Google OAuth2 API.
// It contains the user's ID, email, name, given name, family name, profile picture, and locale.
type OAuthGoogleUserInfo struct {
	ID         string `json:"sub"`
	Email      string `json:"email"`
	Name       string `json:"name"`
	GivenName  string `json:"given_name"`
	FamilyName string `json:"family_name"`
	Picture    string `json:"picture"`
	Locale     string `json:"locale"`
}

// GetUserInfo retrieves the user's information from the Google OAuth2 API using the provided access token.
// It returns a struct containing the user's ID, email, name, given name, family name, profile picture, and locale.
// If an error occurs during the API request or response decoding, the function will return an error.
func GetUserInfo(token *oauth2.Token) (*OAuthGoogleUserInfo, error) {
	client := GoogleOAuthConfig.Client(context.Background(), token)

	resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var userInfo OAuthGoogleUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}

	return &userInfo, nil
}
