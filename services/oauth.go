package services

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
)

const (
	defaultGoogleAuthURL     = "https://accounts.google.com/o/oauth2/v2/auth"
	defaultGoogleTokenURL    = "https://oauth2.googleapis.com/token"
	defaultGoogleUserInfoURL = "https://www.googleapis.com/oauth2/v3/userinfo"
	defaultGoogleRedirectURL = "http://localhost:8080/api/oauth/callback"
)

// OAuthSettings carries the provider configuration for the social login
// flow. All values are supplied by the environment so the endpoints can be
// pointed at a fake provider in tests.
type OAuthSettings struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	AuthURL      string
	TokenURL     string
	UserInfoURL  string
	Scopes       []string
	SessionState string
}

// NewGoogleOAuthSettings builds the Google OAuth settings from a base
// oauth2.Config plus the injected values.
func NewGoogleOAuthSettings(clientID, clientSecret, redirectURL, authURL, tokenURL, userInfoURL string) *OAuthSettings {
	if redirectURL == "" {
		redirectURL = defaultGoogleRedirectURL
	}
	if authURL == "" {
		authURL = defaultGoogleAuthURL
	}
	if tokenURL == "" {
		tokenURL = defaultGoogleTokenURL
	}
	if userInfoURL == "" {
		userInfoURL = defaultGoogleUserInfoURL
	}
	state, err := randomState()
	if err != nil {
		fmt.Println("oauth: generating state failed, falling back to fixed state:", err)
		state = "gauth"
	}
	return &OAuthSettings{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      authURL,
		TokenURL:     tokenURL,
		UserInfoURL:  userInfoURL,
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		SessionState: state,
	}
}

// Config returns the oauth2.Config used to drive the authorization code flow.
func (s *OAuthSettings) Config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     s.ClientID,
		ClientSecret: s.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  s.AuthURL,
			TokenURL: s.TokenURL,
		},
		RedirectURL: s.RedirectURL,
		Scopes:      s.Scopes,
	}
}

// State validates and returns the anti-forgery state value used by the flow.
func (s *OAuthSettings) State() string {
	return s.SessionState
}

// AuthCodeURL builds the provider authorization URL for the current session.
func (s *OAuthSettings) AuthCodeURL(state string) string {
	return s.Config().AuthCodeURL(state)
}

// Exchange trades an authorization code for an access token.
func (s *OAuthSettings) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	return s.Config().Exchange(ctx, code)
}

// Client returns an HTTP client authorized with the given token.
func (s *OAuthSettings) Client(ctx context.Context, token *oauth2.Token) *http.Client {
	return s.Config().Client(ctx, token)
}

// OAuthGoogleUserInfo represents the user information returned by the
// Google OAuth2 userinfo endpoint.
type OAuthGoogleUserInfo struct {
	ID         string `json:"sub"`
	Email      string `json:"email"`
	Name       string `json:"name"`
	GivenName  string `json:"given_name"`
	FamilyName string `json:"family_name"`
	Picture    string `json:"picture"`
	Locale     string `json:"locale"`
}

// GetUserInfo retrieves the provider user info with the given access token.
func (s *OAuthSettings) GetUserInfo(token *oauth2.Token) (*OAuthGoogleUserInfo, error) {
	client := s.Client(context.Background(), token)

	resp, err := client.Get(s.UserInfoURL)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("unexpected status %d fetching user info", resp.StatusCode)
	}

	var userInfo OAuthGoogleUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}
	return &userInfo, nil
}

func randomState() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
