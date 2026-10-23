package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestCallDecodesJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, http.MethodPost, r.Method)
		var payload map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
		assert.Equal(t, map[string]string{"file_id": "42"}, payload)

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"file_path":"/some/path.png"}`)
	}))
	defer server.Close()

	result, err := Call(server.URL, http.MethodPost, []byte(`{"file_id":"42"}`))
	require.NoError(t, err)
	assert.Equal(t, "/some/path.png", result["file_path"])
}

func TestCallEmptyURL(t *testing.T) {
	_, err := Call("", http.MethodGet, nil)
	assert.EqualError(t, err, "empty request url")
}

func TestCallNon200IsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
	}))
	defer server.Close()

	_, err := Call(server.URL, http.MethodGet, nil)
	assert.ErrorContains(t, err, "unexpected status 404")
}

func TestCallInvalidJSONIsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `not-json`)
	}))
	defer server.Close()

	_, err := Call(server.URL, http.MethodGet, nil)
	assert.Error(t, err)
}

func TestCallEmptyBodyReturnsEmptyMap(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	result, err := Call(server.URL, http.MethodGet, nil)
	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestGetUserInfo(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer access-token", r.Header.Get("Authorization"))
		fmt.Fprint(w, `{"sub":"g-42","email":"user@example.com","name":"User Name","given_name":"User","family_name":"Name"}`)
	}))
	defer server.Close()

	oauth := NewGoogleOAuthSettings("client", "secret", "", server.URL, server.URL, server.URL)
	token := &oauth2.Token{AccessToken: "access-token", TokenType: "Bearer"}

	info, err := oauth.GetUserInfo(token)
	require.NoError(t, err)
	assert.Equal(t, "g-42", info.ID)
	assert.Equal(t, "user@example.com", info.Email)
	assert.Equal(t, "User Name", info.Name)
}

func TestGetUserInfoNon200(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer server.Close()

	oauth := NewGoogleOAuthSettings("client", "secret", "", server.URL, server.URL, server.URL)
	_, err := oauth.GetUserInfo(&oauth2.Token{AccessToken: "t"})
	assert.ErrorContains(t, err, "unexpected status 500")
}

func TestNewGoogleOAuthSettingsDefaults(t *testing.T) {
	oauth := NewGoogleOAuthSettings("", "", "", "", "", "")

	assert.Equal(t, defaultGoogleRedirectURL, oauth.RedirectURL)
	assert.Equal(t, defaultGoogleAuthURL, oauth.AuthURL)
	assert.Equal(t, defaultGoogleTokenURL, oauth.TokenURL)
	assert.Equal(t, defaultGoogleUserInfoURL, oauth.UserInfoURL)
	assert.NotEmpty(t, oauth.SessionState)
	assert.NotEmpty(t, oauth.State())
}

func TestOauthExchangeAgainstFakeProvider(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/token", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"at-1","token_type":"Bearer","expires_in":3600}`)
	}))
	defer server.Close()

	oauth := NewGoogleOAuthSettings("client", "secret", "", server.URL, server.URL+"/token", server.URL)

	token, err := oauth.Exchange(context.Background(), "auth-code")
	require.NoError(t, err)
	assert.Equal(t, "at-1", token.AccessToken)
}

func TestDispatchOTPNotificationNoop(t *testing.T) {
	DispatchOTPNotification("", "123456", "user@example.com")
}
