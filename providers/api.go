package providers

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/imanimen/gAuth/middlewares"
	"github.com/imanimen/gAuth/models"
	"github.com/imanimen/gAuth/services"
	"github.com/imanimen/gAuth/utils"
)

// IApi groups the public HTTP handlers of the service.
type IApi interface {
	GetUser(c *gin.Context)
	SendOtp(c *gin.Context)
	ResendOtp(c *gin.Context)
	VerifyOtp(c *gin.Context)
	GetUserTokenPlatform(c *gin.Context)
	Check(c *gin.Context)
	UpdateUserName(c *gin.Context)
	ValidateUserName(c *gin.Context)
	UpdateProfile(c *gin.Context)
	RemoveProfile(c *gin.Context)
	AddCategory(c *gin.Context)
	DeleteCategory(c *gin.Context)
	AllUsers(c *gin.Context)
	SelectedUsers(c *gin.Context)
	UsersPagination(c *gin.Context)
	OauthRedirect(c *gin.Context)
	OauthCallBack(c *gin.Context)

	GetUserByID(id string) (*models.User, error)
	TokenManager() services.TokenManager
}

// Api is the default IApi implementation.
type Api struct {
	Config      IConfig
	Database    IDatabase
	Validations IValidations
	Tokens      services.TokenManager
	OAuth       *services.OAuthSettings
}

// NewApi wires the handler layer.
func NewApi(config IConfig, database IDatabase, validations IValidations, tokens services.TokenManager, oauth *services.OAuthSettings) IApi {
	return &Api{
		Config:      config,
		Database:    database,
		Validations: validations,
		Tokens:      tokens,
		OAuth:       oauth,
	}
}

// TokenManager exposes the JWT token manager for the routed middleware.
func (api *Api) TokenManager() services.TokenManager {
	return api.Tokens
}

// GetUserByID retrieves a user model by ID from the database.
func (api *Api) GetUserByID(id string) (*models.User, error) {
	return api.Database.GetUserByID(id)
}

// GetUser godoc
// @Summary  Get user by ID
// @Description  Returns the public profile of the user with the given ID.
// @Tags  users
// @Produce  json
// @Param  id  path  string  true  "User ID"
// @Success  200  {object}  ResponseUser
// @Failure  401  {object}  ErrorResponse
// @Failure  404  {object}  ErrorResponse
// @Router  /auth/user/{id}  [get]
// @Security  BearerAuth
func (api *Api) GetUser(c *gin.Context) {
	id := c.Param("id")

	user, err := api.Database.GetUserByID(id)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			RespondError(c, http.StatusNotFound, err.Error())
			return
		}
		RespondError(c, http.StatusInternalServerError, err.Error())
		return
	}

	respondAsUser(c, user)
}

// SendOtp godoc
// @Summary  Send OTP code
// @Description  Generates an OTP code for the given email address and sends it via the notification service.
// @Tags  auth
// @Accept  json
// @Produce  json
// @Param  request  body  SendOtpRequest  true  "Email address"
// @Success  200  {object}  ResponseOTP
// @Failure  422  {object}  ErrorResponse
// @Failure  500  {object}  ErrorResponse
// @Router  /api/auth/send  [post]
func (api *Api) SendOtp(c *gin.Context) {
	api.dispatchOtp(c)
}

// ResendOtp godoc
// @Summary  Resend OTP code
// @Description  Regenerates and resends the OTP code for the given email address.
// @Tags  auth
// @Accept  json
// @Produce  json
// @Param  request  body  SendOtpRequest  true  "Email address"
// @Success  200  {object}  ResponseOTP
// @Failure  422  {object}  ErrorResponse
// @Failure  500  {object}  ErrorResponse
// @Router  /api/auth/resend  [post]
func (api *Api) ResendOtp(c *gin.Context) {
	api.dispatchOtp(c)
}

func (api *Api) dispatchOtp(c *gin.Context) {
	var request SendOtpRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		RespondError(c, http.StatusUnprocessableEntity, validationErrorMessage(err, "Invalid email format"))
		return
	}

	code, expireAt, err := api.Database.SendOTP(request.Email)
	if err != nil {
		RespondError(c, http.StatusInternalServerError, err.Error())
		return
	}

	if notifyBase := api.Config.Get("NOTIFY_API_URL"); notifyBase != "" {
		services.DispatchOTPNotification(strings.TrimSuffix(notifyBase, "/")+"/v1/notify", code, request.Email)
	}

	RespondOK(c, OTPData{
		Code:     code,
		ExpireAt: expireAt,
	})
}

// VerifyOtp godoc
// @Summary  Verify OTP code
// @Description  Verifies the OTP code and returns an access token for the resulting user session.
// @Tags  auth
// @Accept  json
// @Produce  json
// @Param  request  body  VerifyOtpRequest  true  "Email, code and platform"
// @Success  200  {object}  ResponseAuth
// @Failure  401  {object}  ErrorResponse
// @Failure  422  {object}  ErrorResponse
// @Failure  500  {object}  ErrorResponse
// @Router  /api/auth/verify  [post]
func (api *Api) VerifyOtp(c *gin.Context) {
	var request VerifyOtpRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		RespondError(c, http.StatusUnprocessableEntity, validationErrorMessage(err, "Invalid request payload"))
		return
	}

	user, err := api.Database.VerifyCode(request.Email, request.Code)
	switch {
	case errors.Is(err, ErrOTPNotFound):
		RespondError(c, http.StatusUnauthorized, "Invalid code")
		return
	case errors.Is(err, ErrOTPExpired):
		RespondError(c, http.StatusUnauthorized, "OTP code expired, please request a new one")
		return
	case errors.Is(err, ErrUserNotFound):
		RespondError(c, http.StatusNotFound, err.Error())
		return
	case err != nil:
		RespondError(c, http.StatusInternalServerError, err.Error())
		return
	}

	token, err := api.Tokens.Generate(user.ID, request.Platform, nil)
	if err != nil {
		RespondError(c, http.StatusInternalServerError, "Failed to generate token")
		return
	}

	RespondOK(c, AuthData{
		UserID: user.ID,
		Step:   user.RegistrationStep,
		Token:  token,
	})
}

// GetUserTokenPlatform godoc
// @Summary  Get token platform
// @Description  Returns the platform claim of the current access token.
// @Tags  auth
// @Produce  json
// @Success  200  {object}  ResponsePlatform
// @Router  /auth/user/platform  [get]
// @Security  BearerAuth
func (api *Api) GetUserTokenPlatform(c *gin.Context) {
	RespondOK(c, PlatformData{
		Platform: middlewares.CurrentPlatform(c),
	})
}

// Check godoc
// @Summary  Check session
// @Description  Returns the authenticated user the current access token belongs to.
// @Tags  users
// @Produce  json
// @Success  200  {object}  ResponseUser
// @Router  /auth/user/check  [get]
// @Security  BearerAuth
func (api *Api) Check(c *gin.Context) {
	user, err := middlewares.CurrentUser(c)
	if err != nil {
		RespondError(c, http.StatusUnauthorized, err.Error())
		return
	}
	respondAsUser(c, &user)
}

// UpdateUserName godoc
// @Summary  Update username
// @Description  Sets the username of the authenticated user.
// @Tags  users
// @Accept  json
// @Produce  json
// @Param  request  body  UpdateUsernameRequest  true  "New username"
// @Success  201  {object}  ResponseUser
// @Failure  422  {object}  ErrorResponse
// @Router  /auth/user/update-username  [post]
// @Security  BearerAuth
func (api *Api) UpdateUserName(c *gin.Context) {
	var request UpdateUsernameRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		RespondError(c, http.StatusUnprocessableEntity, validationErrorMessage(err, "Invalid request payload"))
		return
	}

	if !api.Validations.IsValidUsername(request.Username) {
		RespondError(c, http.StatusUnprocessableEntity, "Invalid username format")
		return
	}

	user, err := middlewares.CurrentUser(c)
	if err != nil {
		RespondError(c, http.StatusUnauthorized, err.Error())
		return
	}

	update, err := api.Database.UpdateUsername(&user, request.Username)
	switch {
	case errors.Is(err, ErrUsernameTaken):
		RespondError(c, http.StatusUnprocessableEntity, "Username already exists")
		return
	case err != nil:
		RespondError(c, http.StatusInternalServerError, err.Error())
		return
	}

	RespondCreated(c, exitUser(update))
}

// ValidateUserName godoc
// @Summary  Validate username
// @Description  Checks that the username is free to pick for the authenticated user.
// @Tags  users
// @Accept  json
// @Produce  json
// @Param  request  body  UpdateUsernameRequest  true  "Username to validate"
// @Success  200  {object}  ResponseAvailability
// @Failure  422  {object}  ErrorResponse
// @Router  /auth/user/validate-username  [post]
// @Security  BearerAuth
func (api *Api) ValidateUserName(c *gin.Context) {
	var request UpdateUsernameRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		RespondError(c, http.StatusUnprocessableEntity, validationErrorMessage(err, "Invalid request payload"))
		return
	}

	if !api.Validations.IsValidUsername(request.Username) {
		RespondError(c, http.StatusUnprocessableEntity,
			"Username must be between 4 and 16 characters and start with a letter and can contain letters, numbers, underscores, and dots")
		return
	}

	user, err := middlewares.CurrentUser(c)
	if err != nil {
		RespondError(c, http.StatusUnauthorized, err.Error())
		return
	}

	if err := api.Database.IsUsernameUnique(request.Username, user.ID); err != nil {
		RespondError(c, http.StatusUnprocessableEntity, "Username already exists")
		return
	}

	RespondOK(c, AvailabilityData{Available: true})
}

// UpdateProfile godoc
// @Summary  Update profile
// @Description  Creates or updates profile key/value pairs for the authenticated user. A `birthdate` value also refreshes the computed `age`.
// @Tags  users
// @Accept  json
// @Produce  json
// @Param  request  body  ProfileUpdateRequest  true  "Profile keys and values"
// @Success  200  {object}  ResponseMessage
// @Failure  422  {object}  ErrorResponse
// @Failure  500  {object}  ErrorResponse
// @Router  /auth/user/update  [post]
// @Security  BearerAuth
func (api *Api) UpdateProfile(c *gin.Context) {
	user, err := middlewares.CurrentUser(c)
	if err != nil {
		RespondError(c, http.StatusUnauthorized, err.Error())
		return
	}

	var request ProfileUpdateRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		RespondError(c, http.StatusUnprocessableEntity, validationErrorMessage(err, "Invalid request payload"))
		return
	}

	for _, item := range request.Keys {
		if err := api.updateProfileItem(user.ID, item); err != nil {
			handleProfileUpdateError(c, err)
			return
		}
	}

	RespondOK(c, MessageData{Message: "Profile updated successfully"})
}

func (api *Api) updateProfileItem(userID string, item KeyItem) error {
	if item.Key == "" {
		return invalidPayloadError{message: "Key is required"}
	}
	if len(item.Value) > maxProfileValueLength {
		return invalidPayloadError{message: "Value exceeds maximum length of 1500 characters"}
	}
	if item.Key == models.KeyBirthday {
		birthDate, err := time.Parse(birthdateFormat, item.Value)
		if err != nil {
			return invalidPayloadError{message: "Invalid birthdate format, expected YYYY/MM/DD"}
		}
		if err := api.Database.UpdateProfile(userID, models.KeyAge, strconv.Itoa(utils.CalculateAge(birthDate))); err != nil {
			return err
		}
	}
	if err := api.Database.UpdateProfile(userID, item.Key, item.Value); err != nil {
		return err
	}
	return nil
}

// RemoveProfile godoc
// @Summary  Remove profile keys
// @Description  Deletes the given profile keys of the authenticated user. Deleting missing keys succeeds silently.
// @Tags  users
// @Accept  json
// @Produce  json
// @Param  request  body  ProfileRemoveRequest  true  "Profile keys to remove"
// @Success  200  {object}  ResponseMessage
// @Failure  422  {object}  ErrorResponse
// @Failure  500  {object}  ErrorResponse
// @Router  /auth/user/remove-profile  [post]
// @Security  BearerAuth
func (api *Api) RemoveProfile(c *gin.Context) {
	user, err := middlewares.CurrentUser(c)
	if err != nil {
		RespondError(c, http.StatusUnauthorized, err.Error())
		return
	}

	var request ProfileRemoveRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		RespondError(c, http.StatusUnprocessableEntity, validationErrorMessage(err, "Invalid request payload"))
		return
	}

	for _, item := range request.Keys {
		if item.Key == "" {
			RespondError(c, http.StatusUnprocessableEntity, "Key is required")
			return
		}
		if err := api.Database.DeleteProfile(user.ID, item.Key); err != nil {
			RespondError(c, http.StatusInternalServerError, "Failed to update profile")
			return
		}
	}

	RespondOK(c, MessageData{Message: "Profile updated successfully"})
}

// AddCategory godoc
// @Summary  Add favorite category
// @Description  Appends a category ID to the authenticated user's favorite categories.
// @Tags  users
// @Accept  json
// @Produce  json
// @Param  request  body  CategoryRequest  true  "Category ID"
// @Success  200  {object}  ResponseMessage
// @Failure  422  {object}  ErrorResponse
// @Router  /auth/user/add-category  [post]
// @Security  BearerAuth
func (api *Api) AddCategory(c *gin.Context) {
	api.handleCategory(c, api.Database.AddCategory)
}

// DeleteCategory godoc
// @Summary  Delete favorite category
// @Description  Removes a category ID from the authenticated user's favorite categories.
// @Tags  users
// @Accept  json
// @Produce  json
// @Param  request  body  CategoryRequest  true  "Category ID"
// @Success  200  {object}  ResponseMessage
// @Failure  422  {object}  ErrorResponse
// @Router  /auth/user/delete-category  [post]
// @Security  BearerAuth
func (api *Api) DeleteCategory(c *gin.Context) {
	api.handleCategory(c, api.Database.DeleteCategory)
}

func (api *Api) handleCategory(c *gin.Context, action func(userId, categoryId string) error) {
	var request CategoryRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		RespondError(c, http.StatusUnprocessableEntity, "category_id is required")
		return
	}

	user, err := middlewares.CurrentUser(c)
	if err != nil {
		RespondError(c, http.StatusUnauthorized, err.Error())
		return
	}

	switch err := action(user.ID, request.CategoryID); {
	case err == nil:
		RespondOK(c, MessageData{Message: "Profile updated successfully"})
	default:
		RespondError(c, http.StatusUnprocessableEntity, err.Error())
	}
}

// AllUsers godoc
// @Summary  List users
// @Description  Lists all users other than the requesting one, filtered by a search query.
// @Tags  users
// @Produce  json
// @Param  q  query  string  false  "Search query"
// @Param  limit  query  integer  false  "Max results"
// @Success  200  {object}  ResponseUsers
// @Failure  500  {object}  ErrorResponse
// @Router  /auth/user/all-users  [get]
// @Security  BearerAuth
func (api *Api) AllUsers(c *gin.Context) {
	searchQuery := c.Query("q")
	limit, _ := strconv.Atoi(c.Query("limit"))

	user, err := middlewares.CurrentUser(c)
	if err != nil {
		RespondError(c, http.StatusUnauthorized, err.Error())
		return
	}

	users := api.Database.AllUsers(user.ID, searchQuery, limit)
	if users == nil {
		RespondError(c, http.StatusInternalServerError, "Failed to fetch users")
		return
	}
	respondAsUsers(c, users)
}

// UsersPagination godoc
// @Summary  List users with pagination
// @Description  Lists users other than the requesting one, paginated and filtered by a search query.
// @Tags  users
// @Produce  json
// @Param  q  query  string  false  "Search query"
// @Param  page  query  integer  true  "Page number (1 based)"
// @Param  pageSize  query  integer  true  "Page size"
// @Success  200  {object}  ResponseUsers
// @Failure  500  {object}  ErrorResponse
// @Router  /auth/user/users  [get]
// @Security  BearerAuth
func (api *Api) UsersPagination(c *gin.Context) {
	searchQuery := c.Query("q")
	page, _ := strconv.Atoi(c.Query("page"))
	pageSize, _ := strconv.Atoi(c.Query("pageSize"))

	user, err := middlewares.CurrentUser(c)
	if err != nil {
		RespondError(c, http.StatusUnauthorized, err.Error())
		return
	}

	users := api.Database.AllUsersWithPagination(user.ID, searchQuery, page, pageSize)
	if users == nil {
		RespondError(c, http.StatusInternalServerError, "Failed to fetch users")
		return
	}
	respondAsUsers(c, users)
}

// SelectedUsers godoc
// @Summary  Get selected users
// @Description  Returns the users matching the given ID list, excluding the requesting user.
// @Tags  users
// @Accept  json
// @Produce  json
// @Param  request  body  SelectUsersRequest  true  "User ID list"
// @Success  200  {object}  ResponseUsers
// @Failure  400  {object}  ErrorResponse
// @Failure  500  {object}  ErrorResponse
// @Router  /auth/user/select  [post]
// @Security  BearerAuth
func (api *Api) SelectedUsers(c *gin.Context) {
	var request SelectUsersRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		RespondError(c, http.StatusBadRequest, "Invalid JSON payload")
		return
	}

	user, err := middlewares.CurrentUser(c)
	if err != nil {
		RespondError(c, http.StatusUnauthorized, err.Error())
		return
	}

	users, err := api.Database.GetUsersByIds(user.ID, request.UserIDs)
	if err != nil {
		RespondError(c, http.StatusInternalServerError, err.Error())
		return
	}
	respondAsUsers(c, users)
}

// OauthRedirect godoc
// @Summary  Start Google OAuth flow
// @Description  Returns the provider authorization URL for the social login flow.
// @Tags  oauth
// @Produce  json
// @Success  200  {object}  ResponseRedirect
// @Failure  500  {object}  ErrorResponse
// @Router  /api/oauth/redirect  [get]
func (api *Api) OauthRedirect(c *gin.Context) {
	RespondOK(c, RedirectData{
		Redirect: api.OAuth.AuthCodeURL(api.OAuth.State()),
	})
}

// OauthCallBack godoc
// @Summary  Google OAuth callback
// @Description  Exchanges the authorization code, links the social account to the user, seeds the profile and returns an access token.
// @Tags  oauth
// @Produce  json
// @Param  code  query  string  true  "Authorization code"
// @Param  state  query  string  true  "State returned by /api/oauth/redirect"
// @Param  platform  query  string  false  "Target platform claim"
// @Success  200  {object}  ResponseAuth
// @Failure  400  {object}  ErrorResponse
// @Router  /api/oauth/callback  [get]
func (api *Api) OauthCallBack(c *gin.Context) {
	code := c.Query("code")
	platform := c.Query("platform")

	if code == "" {
		RespondError(c, http.StatusBadRequest, "Missing authorization code")
		return
	}
	if api.OAuth.SessionState != "" && c.Query("state") != api.OAuth.SessionState {
		RespondError(c, http.StatusBadRequest, "Invalid OAuth state")
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	token, err := api.OAuth.Exchange(ctx, code)
	if err != nil {
		RespondError(c, http.StatusBadRequest, "Failed to exchange authorization code for token")
		return
	}

	googleUserInfo, err := api.OAuth.GetUserInfo(token)
	if err != nil {
		RespondError(c, http.StatusInternalServerError, "Failed to get user info")
		return
	}

	user, err := api.Database.OauthGetOrCreateUser(googleUserInfo.Email, googleUserInfo.GivenName)
	if err != nil {
		RespondError(c, http.StatusBadRequest, err.Error())
		return
	}

	if err := api.Database.CreateSocialAuthClient("google", user.ID, googleUserInfo.ID); err != nil {
		RespondError(c, http.StatusBadRequest, err.Error())
		return
	}

	profile := map[string]string{
		models.KeyFirstName:   googleUserInfo.GivenName,
		models.KeyLastName:    googleUserInfo.FamilyName,
		models.KeyDisplayName: googleUserInfo.Name,
		models.KeyUsername:    googleUserInfo.GivenName,
	}
	for key, value := range profile {
		if value == "" {
			continue
		}
		if err := api.Database.UpdateProfile(user.ID, key, value); err != nil {
			RespondError(c, http.StatusBadRequest, err.Error())
			return
		}
	}

	jwtToken, err := api.Tokens.Generate(user.ID, platform, nil)
	if err != nil {
		RespondError(c, http.StatusInternalServerError, "Failed to sign JWT token")
		return
	}

	RespondOK(c, AuthData{
		UserID: user.ID,
		Step:   user.RegistrationStep,
		Token:  jwtToken,
	})
}

// --- helpers ---

const (
	birthdateFormat       = "2006/01/02"
	maxProfileValueLength = 1500
)

type invalidPayloadError struct {
	message string
}

func (e invalidPayloadError) Error() string {
	return e.message
}

// exitUser converts the database user into its public representation.
func exitUser(user *models.User) models.User {
	if user == nil {
		return models.User{}
	}
	return *user
}

func respondAsUser(c *gin.Context, user *models.User) {
	RespondOK(c, exitUser(user))
}

func respondAsUsers(c *gin.Context, users []models.User) {
	if users == nil {
		users = []models.User{}
	}
	RespondOK(c, users)
}

// validationErrorMessage keeps binding errors short and human readable.
func validationErrorMessage(bindErr error, fallback string) string {
	msg := bindErr.Error()
	if strings.Contains(msg, "required") || strings.Contains(msg, "email") {
		return fallback
	}
	return msg
}

func handleProfileUpdateError(c *gin.Context, err error) {
	if payloadErr, ok := err.(invalidPayloadError); ok {
		RespondError(c, http.StatusUnprocessableEntity, payloadErr.message)
		return
	}
	RespondError(c, http.StatusInternalServerError, err.Error())
}
