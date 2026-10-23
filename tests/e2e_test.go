package e2e

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	gsqlite "github.com/glebarez/sqlite"
	_ "github.com/imanimen/gAuth/docs"
	"github.com/imanimen/gAuth/invokers"
	"github.com/imanimen/gAuth/models"
	"github.com/imanimen/gAuth/providers"
	"github.com/imanimen/gAuth/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// --- harness ---

type envelope struct {
	Version string          `json:"version"`
	Data    json.RawMessage `json:"data"`
	Error   string          `json:"error"`
}

type authData struct {
	UserID string `json:"user_id"`
	Step   int    `json:"step"`
	Token  string `json:"token"`
}

type otpData struct {
	Code     string `json:"code"`
	ExpireAt string `json:"expire_at"`
}

type harness struct {
	t       *testing.T
	server  *httptest.Server
	oauth   *httptest.Server
	version string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	gin.SetMode(gin.TestMode)

	// fake google endpoints
	oauth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/token":
			assert.Equal(t, http.MethodPost, r.Method)
			fmt.Fprint(w, `{"access_token":"fake-access-token","token_type":"Bearer","expires_in":3600}`)
		case "/userinfo":
			fmt.Fprint(w, `{"sub":"g-sub-1","email":"googleuser@example.com","name":"Google User","given_name":"Google","family_name":"User"}`)
		default:
			http.NotFound(w, r)
		}
	}))

	cfg := providers.NewTestConfig(map[string]string{
		"apiVersion":           "vtest",
		"SECRET":               "e2e-signing-secret",
		"GOOGLE_CLIENT_ID":     "fake-client",
		"GOOGLE_CLIENT_SECRET": "fake-secret",
		"GOOGLE_AUTH_URL":      oauth.URL + "/auth",
		"GOOGLE_TOKEN_URL":     oauth.URL + "/token",
		"GOOGLE_USERINFO_URL":  oauth.URL + "/userinfo",
		"ENABLE_SWAGGER":       "1",
	})

	db, err := gorm.Open(gsqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() {
		_ = sqlDB.Close()
		oauth.Close()
	})

	database := providers.NewDatabase(db)
	tokens := providers.NewTokenManager(cfg)
	oauthSettings := providers.NewOAuth(cfg)
	api := providers.NewApi(cfg, database, providers.NewValidations(), tokens, oauthSettings)
	engine := invokers.NewRouter(cfg, api)

	server := httptest.NewServer(engine)
	t.Cleanup(server.Close)

	return &harness{t: t, server: server, oauth: oauth, version: "vtest"}
}

func (h *harness) do(method, path, token string, body interface{}, contentType string) (int, envelope) {
	h.t.Helper()

	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		require.NoError(h.t, err)
		reader = strings.NewReader(string(raw))
	}

	req, err := http.NewRequest(method, h.server.URL+path, reader)
	require.NoError(h.t, err)
	if body != nil {
		if contentType == "" {
			req.Header.Set("Content-Type", "application/json")
		} else {
			req.Header.Set("Content-Type", contentType)
		}
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(req)
	require.NoError(h.t, err)
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	require.NoError(h.t, err)

	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		env = envelope{Error: strings.TrimSpace(string(raw))}
	}
	return resp.StatusCode, env
}

func (h *harness) post(path, token string, body interface{}) (int, envelope) {
	return h.do(http.MethodPost, path, token, body, "")
}

func (h *harness) get(path, token string) (int, envelope) {
	return h.do(http.MethodGet, path, token, nil, "")
}

// signUser runs the OTP flow for an email and returns the verified user data.
func (h *harness) signUser(email, platform string) authData {
	h.t.Helper()

	status, env := h.post("/api/auth/send", "", map[string]string{"email": email})
	require.Equal(h.t, http.StatusOK, status, env.Error)

	code := requireDecode[otpData](h.t, env)
	status, verifyEnv := h.post("/api/auth/verify", "", map[string]string{
		"email":    email,
		"code":     code.Code,
		"platform": platform,
	})
	require.Equal(h.t, http.StatusOK, status, verifyEnv.Error)
	return requireDecode[authData](h.t, verifyEnv)
}

func requireDecode[T any](t *testing.T, env envelope) T {
	t.Helper()
	var decoded T
	require.NoError(t, json.Unmarshal(env.Data, &decoded), "envelope data: %s", env.Data)
	return decoded
}

// --- tests ---

func TestSendOTP(t *testing.T) {
	h := newHarness(t)

	status, env := h.post("/api/auth/send", "", map[string]string{"email": "welcome@example.com"})
	require.Equal(t, http.StatusOK, status)

	data := requireDecode[otpData](t, env)
	assert.Len(t, data.Code, 6)
	assert.NotEmpty(t, data.ExpireAt)
	assert.Equal(t, h.version, env.Version)
}

func TestResendOTP(t *testing.T) {
	h := newHarness(t)

	_, first := h.post("/api/auth/send", "", map[string]string{"email": "resend@example.com"})
	code1 := requireDecode[otpData](t, first)

	status, resend := h.post("/api/auth/resend", "", map[string]string{"email": "resend@example.com"})
	require.Equal(t, http.StatusOK, status)
	code2 := requireDecode[otpData](t, resend)

	assert.NotEqual(t, code1.Code, code2.Code)
}

func TestSendOTPInvalidEmail(t *testing.T) {
	h := newHarness(t)

	status, env := h.post("/api/auth/send", "", map[string]string{"email": "nope"})
	require.Equal(t, http.StatusUnprocessableEntity, status)
	assert.NotEmpty(t, env.Error)
	assert.Equal(t, h.version, env.Version)
}

func TestVerifyOTPWrongCode(t *testing.T) {
	h := newHarness(t)

	_, _ = h.post("/api/auth/send", "", map[string]string{"email": "wrong@example.com"})
	status, env := h.post("/api/auth/verify", "", map[string]string{
		"email": "wrong@example.com", "code": "000000", "platform": "web",
	})
	require.Equal(t, http.StatusUnauthorized, status)
	assert.NotEmpty(t, env.Error)
}

func TestVerifyOTPCodeNotReplayable(t *testing.T) {
	h := newHarness(t)

	status, sent := h.post("/api/auth/send", "", map[string]string{"email": "replay@example.com"})
	require.Equal(t, http.StatusOK, status)
	code := requireDecode[otpData](t, sent)

	status, env := h.post("/api/auth/verify", "", map[string]string{
		"email": "replay@example.com", "code": code.Code, "platform": "web",
	})
	require.Equal(t, http.StatusOK, status, env.Error)

	status, env = h.post("/api/auth/verify", "", map[string]string{
		"email": "replay@example.com", "code": code.Code, "platform": "web",
	})
	require.Equal(t, http.StatusUnauthorized, status)
	assert.Equal(t, "Invalid code", env.Error)
}

func TestAuthorizedEndpointsRejectMissingToken(t *testing.T) {
	h := newHarness(t)

	status, env := h.get("/auth/user/check", "")
	require.Equal(t, http.StatusUnauthorized, status)
	assert.Equal(t, "authorization token is required", env.Error)

	status, env = h.get("/auth/user/check", "garbage-token")
	require.Equal(t, http.StatusUnauthorized, status)
	assert.NotEmpty(t, env.Error)
}

func TestPublicUserRouteDropped(t *testing.T) {
	h := newHarness(t)

	status, _ := h.get("/api/user/some-id", "")
	assert.Equal(t, http.StatusNotFound, status) // route removed on purpose
}

func TestSwaggerUIMounted(t *testing.T) {
	h := newHarness(t)

	resp, err := http.Get(h.server.URL + "/swagger/index.html")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	raw, err := fetchBytes(h.server.URL + "/swagger/doc.json")
	require.NoError(t, err)
	assert.Contains(t, string(raw), "gAuth API")
}

func fetchBytes(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func TestFullUserLifecycle(t *testing.T) {
	h := newHarness(t)

	auth := h.signUser("lifecycle@example.com", "web")
	require.Equal(t, models.SecondStep, auth.Step)
	require.NotEmpty(t, auth.Token)

	// check session
	status, env := h.get("/auth/user/check", auth.Token)
	require.Equal(t, http.StatusOK, status)
	user := requireDecode[models.User](t, env)
	assert.Equal(t, auth.UserID, user.ID)
	assert.Equal(t, "lifecycle@example.com", user.Email)

	// platform claim
	status, env = h.get("/auth/user/platform", auth.Token)
	require.Equal(t, http.StatusOK, status)
	assert.JSONEq(t, `{"platform":"web"}`, string(env.Data))

	// update username -> step 3
	status, env = h.post("/auth/user/update-username", auth.Token, map[string]string{"username": "lifecyclenick"})
	require.Equal(t, http.StatusCreated, status, env.Error)
	updated := requireDecode[models.User](t, env)
	assert.Equal(t, "lifecyclenick", updated.Username)

	status, env = h.get("/auth/user/"+auth.UserID, auth.Token)
	require.Equal(t, http.StatusOK, status)
	user = requireDecode[models.User](t, env)
	assert.Equal(t, models.ThirdStep, user.RegistrationStep)

	// validate username availability
	status, env = h.post("/auth/user/validate-username", auth.Token, map[string]string{"username": "lifecyclenick"})
	require.Equal(t, http.StatusOK, status, env.Error)
	assert.JSONEq(t, `{"available":true}`, string(env.Data))

	// invalid usernames
	status, env = h.post("/auth/user/update-username", auth.Token, map[string]string{"username": "ab"})
	require.Equal(t, http.StatusUnprocessableEntity, status)

	// profile update
	status, env = h.post("/auth/user/update", auth.Token, map[string]interface{}{
		"keys": []map[string]string{
			{"key": "first_name", "value": "Jane"},
			{"key": "last_name", "value": "Doe"},
		},
	})
	require.Equal(t, http.StatusOK, status, env.Error)
	status, env = h.get("/auth/user/check", auth.Token)
	require.Equal(t, http.StatusOK, status)
	user = requireDecode[models.User](t, env)
	assert.Equal(t, "Jane", user.FirstName)
	assert.Equal(t, "Doe", user.LastName)

	// birthdate refreshes age
	birthYear := time.Now().AddDate(-28, 0, 1) // 27 full years reached
	status, env = h.post("/auth/user/update", auth.Token, map[string]interface{}{
		"keys": []map[string]string{
			{"key": "birthdate", "value": birthYear.Format("2006/01/02")},
		},
	})
	require.Equal(t, http.StatusOK, status, env.Error)
	status, env = h.get("/auth/user/check", auth.Token)
	user = requireDecode[models.User](t, env)
	assert.Equal(t, "27", user.Age)

	// categories -> step 4
	status, env = h.post("/auth/user/update", auth.Token, map[string]interface{}{
		"keys": []map[string]string{{"key": "favorite_categories", "value": "10,20"}},
	})
	require.Equal(t, http.StatusOK, status, env.Error)

	status, env = h.post("/auth/user/add-category", auth.Token, map[string]string{"category_id": "30"})
	require.Equal(t, http.StatusOK, status, env.Error)

	status, env = h.post("/auth/user/add-category", auth.Token, map[string]string{"category_id": "30"})
	require.Equal(t, http.StatusUnprocessableEntity, status)

	status, env = h.get("/auth/user/check", auth.Token)
	user = requireDecode[models.User](t, env)
	assert.Equal(t, "10,20,30", user.FavoriteCategories)
	assert.Equal(t, models.FourthStep, user.RegistrationStep)

	status, env = h.post("/auth/user/delete-category", auth.Token, map[string]string{"category_id": "20"})
	require.Equal(t, http.StatusOK, status, env.Error)
	status, env = h.get("/auth/user/check", auth.Token)
	user = requireDecode[models.User](t, env)
	assert.Equal(t, "10,30", user.FavoriteCategories)

	// remove profile
	status, env = h.post("/auth/user/remove-profile", auth.Token, map[string]interface{}{
		"keys": []map[string]string{{"key": "first_name"}},
	})
	require.Equal(t, http.StatusOK, status, env.Error)
	status, env = h.get("/auth/user/check", auth.Token)
	user = requireDecode[models.User](t, env)
	assert.Empty(t, user.FirstName)
}

func TestUsernameUniquenessAcrossUsers(t *testing.T) {
	h := newHarness(t)

	first := h.signUser("first@example.com", "web")
	require.Equal(t, http.StatusCreated, func() int {
		status, _ := h.post("/auth/user/update-username", first.Token, map[string]string{"username": "sharednick"})
		return status
	}())

	second := h.signUser("second@example.com", "web")

	status, env := h.post("/auth/user/validate-username", second.Token, map[string]string{"username": "sharednick"})
	require.Equal(t, http.StatusUnprocessableEntity, status)
	assert.Equal(t, "Username already exists", env.Error)

	status, _ = h.post("/auth/user/update-username", second.Token, map[string]string{"username": "sharednick"})
	require.Equal(t, http.StatusUnprocessableEntity, status)
}

func TestUserListEndpoints(t *testing.T) {
	h := newHarness(t)

	main := h.signUser("listme@example.com", "web")
	other1 := h.signUser("other1@example.com", "web")
	other2 := h.signUser("other2@example.com", "web")

	h.post("/auth/user/update-username", main.Token, map[string]string{"username": "mainnick"})
	h.post("/auth/user/update-username", other1.Token, map[string]string{"username": "other1nick"})
	h.post("/auth/user/update-username", other2.Token, map[string]string{"username": "other2nick"})

	status, env := h.get("/auth/user/all-users?limit=50", main.Token)
	require.Equal(t, http.StatusOK, status, env.Error)
	allUsers := requireDecode[[]models.User](t, env)
	require.Len(t, allUsers, 2)

	status, env = h.get("/auth/user/users?page=1&pageSize=1", main.Token)
	require.Equal(t, http.StatusOK, status, env.Error)
	page1 := requireDecode[[]models.User](t, env)
	require.Len(t, page1, 1)

	status, env = h.get("/auth/user/users?page=2&pageSize=1", main.Token)
	require.Equal(t, http.StatusOK, status, env.Error)
	page2 := requireDecode[[]models.User](t, env)
	require.Len(t, page2, 1)
	assert.NotEqual(t, page1[0].ID, page2[0].ID)

	status, env = h.post("/auth/user/select", main.Token, map[string]interface{}{
		"ids": []string{other1.UserID, other2.UserID, main.UserID},
	})
	require.Equal(t, http.StatusOK, status, env.Error)
	selected := requireDecode[[]models.User](t, env)
	require.Len(t, selected, 2)

	status, env = h.get("/auth/user/all-users?q=other2nick", main.Token)
	require.Equal(t, http.StatusOK, status)
	filtered := requireDecode[[]models.User](t, env)
	require.Len(t, filtered, 1)
	assert.Equal(t, other2.UserID, filtered[0].ID)
}

func TestOAuthFlow(t *testing.T) {
	h := newHarness(t)

	status, env := h.get("/api/oauth/redirect", "")
	require.Equal(t, http.StatusOK, status, env.Error)
	redirect := requireDecode[struct {
		Redirect string `json:"redirect"`
	}](t, env)
	parsed, err := url.Parse(redirect.Redirect)
	require.NoError(t, err)
	assert.Equal(t, h.oauth.URL+"/auth", parsed.Scheme+"://"+parsed.Host+parsed.Path)
	assert.Equal(t, "fake-client", parsed.Query().Get("client_id"))
	state := parsed.Query().Get("state")
	require.NotEmpty(t, state)

	// state must match
	status, env = h.do(http.MethodGet, "/api/oauth/callback?code=c&platform=web", "", nil, "")
	require.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "Invalid OAuth state", env.Error)

	status, env = h.do(http.MethodGet, "/api/oauth/callback?code=c&state="+state+"&platform=web", "", nil, "")
	require.Equal(t, http.StatusOK, status, env.Error)
	auth := requireDecode[authData](t, env)
	require.NotEmpty(t, auth.Token)
	assert.Equal(t, models.SecondStep, auth.Step)

	// linked user is reachable, profile was seeded
	status, env = h.get("/auth/user/check", auth.Token)
	require.Equal(t, http.StatusOK, status, env.Error)
	user := requireDecode[models.User](t, env)
	assert.Equal(t, "googleuser@example.com", user.Email)
	assert.Equal(t, "Google", user.FirstName)

	// token carries the platform claim
	status, env = h.get("/auth/user/platform", auth.Token)
	require.Equal(t, http.StatusOK, status)
	assert.JSONEq(t, `{"platform":"web"}`, string(env.Data))
}

func TestOAuthCallbackMissingCode(t *testing.T) {
	h := newHarness(t)

	status, _ := h.do(http.MethodGet, "/api/oauth/callback?state=x", "", nil, "")
	assert.Equal(t, http.StatusBadRequest, status)
}

func TestAccessTokenExpiryWindow(t *testing.T) {
	h := newHarness(t)

	auth := h.signUser("expiry@example.com", "web")
	require.NotEmpty(t, auth.Token)

	manager := services.NewJWTManager("e2e-signing-secret", 10*time.Minute)
	claims, err := manager.Parse(auth.Token)
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().Add(10*time.Minute), claims.ExpiresAt.Time, 30*time.Second)
}
