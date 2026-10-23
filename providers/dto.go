package providers

import "github.com/imanimen/gAuth/models"

// SendOtpRequest is the payload for the send-otp endpoints.
type SendOtpRequest struct {
	Email string `json:"email" binding:"required,email"`
}

// VerifyOtpRequest is the payload for the verify-otp endpoint.
type VerifyOtpRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Code     string `json:"code" binding:"required"`
	Platform string `json:"platform" binding:"required"`
}

// UpdateUsernameRequest is the payload for the username endpoints.
type UpdateUsernameRequest struct {
	Username string `json:"username" binding:"required"`
}

// KeyItem is a single profile key/value pair.
type KeyItem struct {
	Key   string `json:"key" binding:"required"`
	Value string `json:"value"`
}

// ProfileUpdateRequest is the payload for updating profile key/values.
type ProfileUpdateRequest struct {
	Keys []KeyItem `json:"keys" binding:"required,dive"`
}

// ProfileRemoveRequest is the payload for removing profile key/values.
type ProfileRemoveRequest struct {
	Keys []KeyItem `json:"keys" binding:"required,dive"`
}

// CategoryRequest is the payload for the category endpoints.
type CategoryRequest struct {
	CategoryID string `json:"category_id" binding:"required"`
}

// SelectUsersRequest is the payload for selecting users by id list.
type SelectUsersRequest struct {
	UserIDs []string `json:"ids" binding:"required,min=1,dive"`
}

// OTPData is the payload of the send-otp responses.
type OTPData struct {
	Code     string `json:"code"`
	ExpireAt string `json:"expire_at"`
}

// AuthData is the payload of the token issuing responses.
type AuthData struct {
	UserID string `json:"user_id"`
	Step   int    `json:"step"`
	Token  string `json:"token"`
}

// PlatformData is the payload of the platform claim response.
type PlatformData struct {
	Platform string `json:"platform"`
}

// AvailabilityData is the payload of the username availability response.
type AvailabilityData struct {
	Available bool `json:"available"`
}

// MessageData is the payload of simple acknowledgement responses.
type MessageData struct {
	Message string `json:"message"`
}

// RedirectData is the payload of the OAuth start response.
type RedirectData struct {
	Redirect string `json:"redirect"`
}

// ResponseUser is the envelope returned for single user endpoints.
type ResponseUser struct {
	Version string      `json:"version"`
	Data    models.User `json:"data"`
}

// ResponseUsers is the envelope returned for user list endpoints.
type ResponseUsers struct {
	Version string        `json:"version"`
	Data    []models.User `json:"data"`
}

// ResponseOTP is the envelope returned by the send-otp endpoints.
type ResponseOTP struct {
	Version string  `json:"version"`
	Data    OTPData `json:"data"`
}

// ResponseAuth is the envelope returned by the token issuing endpoints.
type ResponseAuth struct {
	Version string   `json:"version"`
	Data    AuthData `json:"data"`
}

// ResponsePlatform is the envelope returned by the platform claim endpoint.
type ResponsePlatform struct {
	Version string       `json:"version"`
	Data    PlatformData `json:"data"`
}

// ResponseAvailability is the envelope of the username availability check.
type ResponseAvailability struct {
	Version string           `json:"version"`
	Data    AvailabilityData `json:"data"`
}

// ResponseMessage is the envelope of simple acknowledgement responses.
type ResponseMessage struct {
	Version string      `json:"version"`
	Data    MessageData `json:"data"`
}

// ResponseRedirect is the envelope of the OAuth start response.
type ResponseRedirect struct {
	Version string       `json:"version"`
	Data    RedirectData `json:"data"`
}

// ErrorResponse is the envelope returned on failures.
type ErrorResponse struct {
	Version string `json:"version"`
	Error   string `json:"error"`
}
