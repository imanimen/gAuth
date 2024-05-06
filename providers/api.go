package providers

import (
	"context"
	_ "fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/imanimen/gAuth/services"
	"github.com/imanimen/gAuth/utils"

	// "git.dyneemadev.com/micro-services/go-auth/models"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/imanimen/gAuth/models"
)

type IApi interface {
	GetUser(c *gin.Context)
	SendOtp(c *gin.Context)
	ResendOtp(c *gin.Context)
	VerifyOtp(c *gin.Context)
	GetUserById(id string) (*models.User, error)
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
}

type Api struct {
	Config      IConfig
	Database    IDatabase
	Validations IValidations
}

func NewApi(config IConfig, database IDatabase, validations IValidations) IApi {
	return &Api{
		Config:      config,
		Database:    database,
		Validations: validations,
	}
}

// GetUserById retrieves a user model by ID from the database.
func (api *Api) GetUserById(id string) (*models.User, error) {
	return api.Database.getUserByID(id)
}

// GetUser retrieves the user with the given ID from the database
// and returns it in the response. It gets the ID from the URL param "id",
// looks up the user in the database using the APIs Database provider,
// and returns a JSON response containing the API version and user data.
// Returns a 200 OK status code.
func (api *Api) GetUser(c *gin.Context) {
	id := c.Param("id")
	user, _ := api.Database.getUserByID(id)
	c.JSON(http.StatusOK, gin.H{
		"version": api.Config.Get("apiVersion"),
		"data":    user,
	})
}

// SendOtp sends a one-time password code to the provided email address.
// It generates a random OTP code, stores it with an expiration timestamp in the database,
// and dispatches a notification to send the OTP code to the user.
// Returns the OTP code, expiration timestamp, and any error from the database layer.
func (api *Api) SendOtp(c *gin.Context) {
	email := c.PostForm("email")
	if !api.Validations.IsValidEmail(email) {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"error": "Invalid email format",
		})
		return
	}
	code, expireAt, err := api.Database.sendOTP(email)
	// TODO: Uncomment on production level,
	/*
		payloadData := []byte(`{
			"type": ["email"],
			"payload": "` + code + `",
			"destination": "` + email + `",
			"mail_type": "otp"
		}`)

		// TODO:  Error handle the channel
		go func() {
			_, err := services.Call(api.Config.Get("NOTIFY_API_URL")+"/v1/notify", "POST", payloadData)
			if err != nil {
				return
			}
		}()
	*/
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"version": api.Config.Get("apiVersion"),
		"data": gin.H{
			"code":      code,
			"expire_at": expireAt,
		},
	})
}

// ResendOtp re-send a one-time password code to the provided email address.
// It re-generates a random OTP code, stores it with a new expiration timestamp in the database,
// and dispatches a notification to re-send the OTP code to the user.
// Returns the new OTP code, new expiration timestamp, and any error from the database layer.
func (api *Api) ResendOtp(c *gin.Context) {
	email := c.PostForm("email")
	if !api.Validations.IsValidEmail(email) {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"error": "Invalid email format",
		})
		return
	}
	code, expireAt, err := api.Database.sendOTP(email)
	// TODO: Uncomment on production level,
	/*
		payloadData := []byte(`{
			"type": ["email"],
			"payload": "` + code + `",
			"destination": "` + email + `",
			"mail_type": "otp"
		}`)

		// TODO:  Error handle the channel
		go func() {
			_, err := services.Call(api.Config.Get("NOTIFY_API_URL")+"/v1/notify", "POST", payloadData)
			if err != nil {
				return
			}
		}()
	*/
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"version": api.Config.Get("apiVersion"),
		"data": gin.H{
			"code":      code,
			"expire_at": expireAt,
		},
	})
}

// VerifyOtp verifies a one-time password code that was sent to the
// provided email address. It checks the code against the database,
// generates a JWT token if valid, and returns user info, token, and any errors.
func (api *Api) VerifyOtp(c *gin.Context) {
	email := c.PostForm("email")
	code := c.PostForm("code")
	platform := c.PostForm("platform")
	if !api.Validations.IsValidEmail(email) {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"error": "Invalid email format",
		})
		return
	}
	result, err := api.Database.verifyCode(email, code)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	// Generate JWT token
	tokenString, err := services.GenerateJWT(result.ID, map[string]string{"platform": platform})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	// Return the JWT token along with other information
	c.JSON(http.StatusOK, gin.H{
		"version": api.Config.Get("apiVersion"),
		"step":    result.RegistrationStep,
		"user_id": result.ID,
		"token":   tokenString,
	})
}

// GetUserTokenPlatform extracts the "platform" claim from a JWT token
// passed in the Authorization header. It verifies the token is valid,
// returns the platform if found, or handles any errors.
func (api *Api) GetUserTokenPlatform(c *gin.Context) {
	tokenString := c.GetHeader("Authorization")

	platform, err := services.GetValueFromToken(tokenString, "platform")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	}

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"platform": platform,
		},
	})

}

// Check validates a JWT token from the Authorization header,
// extracting the user_id claim and returning the user data.
// It handles invalid tokens and errors gracefully.
func (api *Api) Check(c *gin.Context) {
	user, err := api.GetUserFromToken(c)
	if err != nil {
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": user})
}

// UpdateUserName updates the username for the authenticated user.
// It validates the username format, parses the JWT token to get the user ID,
// retrieves the user from the database, and updates the username,
// returning the updated user data. It handles errors gracefully.
func (api *Api) UpdateUserName(c *gin.Context) {
	username := c.PostForm("username")

	if !api.Validations.IsValidUsername(username) {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"error": "Invalid username format",
		})
		return
	}
	user, err := api.GetUserFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"error": err.Error(),
		})
		return
	}
	u := &user
	update, err := api.Database.updateUsername(u, username)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"error": err.Error(),
		})
		return
	}
	c.JSON(http.StatusCreated, gin.H{
		"data": update,
	})
}

// ValidateUserName validates a username from a POST request.
// It checks that the username is valid format, unique for the user,
// and returns appropriate error responses if not valid.
func (api *Api) ValidateUserName(c *gin.Context) {
	username := c.PostForm("username")

	if !api.Validations.IsValidUsername(username) {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"error": "Username must be between 4 and 16 characters and start with a letter and can contain letters, numbers, underscores, and dots",
		})
		return
	}
	user, err := api.GetUserFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"error": err.Error(),
		})
		return
	}

	errorCheck := api.Database.isUsernameUnique(username, user.ID)
	if errorCheck != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"error": "Username already exists",
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data": errorCheck,
	})
}

type KeyItem struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// UpdateProfile handles updating a user's profile information. It takes a context
// parameter which contains the current user's ID. It binds the update keys and values
// from the request body. It validates each key/value, checking for required keys,
// max lengths, valid usernames, and unique usernames. For each key, it calls the database
// layer to update the user's profile. It returns success/error responses.
func (api *Api) UpdateProfile(c *gin.Context) {
	u, err := api.GetUserFromToken(c)
	if err != nil {
		return
	}

	var keys struct {
		Keys []KeyItem `json:"keys"`
	}
	if err := c.ShouldBindJSON(&keys); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"errors": err.Error()})
		return
	}

	for _, item := range keys.Keys {

		if item.Key == "" {
			c.JSON(http.StatusUnprocessableEntity, gin.H{"errors": "Key is required"})
			return
		}

		if len(item.Value) > 1500 {
			c.JSON(http.StatusUnprocessableEntity, gin.H{"errors": "Value exceeds maximum length of 1500 characters"})
			return
		}
		if item.Key == "birthdate" {
			// Convert birthday to age
			layout := "2006/01/02" // The layout string specifies the format of the input date

			birthDate, err := time.Parse(layout, item.Value)
			if err != nil {
				c.JSON(http.StatusUnprocessableEntity, gin.H{"errors": err.Error()})

				return
			}

			age := utils.CalculateAge(birthDate)
			err = api.Database.updateProfile(u.ID, models.KeyAge, strconv.Itoa(age))
			if err != nil {
				c.JSON(http.StatusUnprocessableEntity, gin.H{"errors": err.Error()})

				return
			}
		}

		err := api.Database.updateProfile(u.ID, item.Key, item.Value)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"errors": err.Error()})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "Profile updated successfully"})
}

// GetUserFromToken extracts the user ID from the provided JWT token in the
// Authorization header, looks up the corresponding user in the database,
// and returns the user object. It handles validation and errors.
func (api *Api) GetUserFromToken(c *gin.Context) (user models.User, err error) {
	tokenString := c.Request.Header.Get("Authorization")
	if strings.HasPrefix(tokenString, "Bearer ") {
		tokenString = strings.TrimPrefix(tokenString, "Bearer ")
	}
	if tokenString == "" {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"error": "Authorization token is required",
		})
		return
	}
	// Parse the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("SECRET")), nil
	})

	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	// Check if the token is valid
	if !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		user_id, exists := claims["user_id"].(string)
		if !exists {
			c.JSON(http.StatusBadRequest, gin.H{"error": "user_id not found in token"})
			return
		}

		user, err := api.Database.getUserByID(user_id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": err.Error(),
			})
			return *user, err
		}
		return *user, nil
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid token claims"})
	}
	return user, nil
}

// RemoveProfile removes profile keys for the authenticated user.
// It takes a JSON body containing a list of keys to remove, validates the input,
// calls the database to delete the keys, and returns a success response.
// It handles errors and returns error responses.
func (api *Api) RemoveProfile(c *gin.Context) {
	// TODO: add validation to delete specific keys
	user, err := api.GetUserFromToken(c)
	if err != nil {
		return
	}

	var keys struct {
		Keys []KeyItem `json:"keys"`
	}
	if err := c.ShouldBindJSON(&keys); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"errors": err.Error()})
		return
	}

	for _, item := range keys.Keys {

		if item.Key == "" {
			c.JSON(http.StatusUnprocessableEntity, gin.H{"errors": "Key is required"})
			return
		}

		err := api.Database.deleteProfile(user.ID, item.Key)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"errors": "Failed to update profile"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "Profile updated successfully"})
}

// AddCategory adds a category ID to the authenticated user's profile.
// It validates the input, calls the database to update the user's profile,
// and returns a response indicating success or failure.
// It handles validation errors and database errors.
func (api *Api) AddCategory(c *gin.Context) {
	categoryId := c.PostForm("category_id")
	user, err := api.GetUserFromToken(c)
	if err != nil {
		return
	}

	if categoryId == "" {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"error": "category_id is required",
		})
		return
	}

	update := api.Database.addCategory(user.ID, categoryId)
	if update != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"errors": update.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Profile updated successfully"})
}

// DeleteCategory removes a category ID from the authenticated user's profile.
// It validates the input, calls the database to update the user's profile,
// and returns a response indicating success or failure.
// It handles validation errors and database errors.
func (api *Api) DeleteCategory(c *gin.Context) {
	categoryId := c.PostForm("category_id")
	user, err := api.GetUserFromToken(c)
	if err != nil {
		return
	}

	if categoryId == "" {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"error": "category_id is required",
		})
		return
	}

	update := api.Database.deleteCategory(user.ID, categoryId)
	if update != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"errors": update.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Profile updated successfully"})
}

// AllUsers retrieves all users that match the given search query.
// It authenticates the request using the provided token, calls the database
// to retrieve the filtered list of users, and returns the result.
func (api *Api) AllUsers(c *gin.Context) {
	searchQuery := c.Query("q")
	limitStr := c.Query("limit")
	user, err := api.GetUserFromToken(c)
	if err != nil {
		return
	}

	// Convert the limit parameter to an integer
	limit, _ := strconv.Atoi(limitStr)
	users := api.Database.allUsers(user.ID, searchQuery, limit)
	c.JSON(http.StatusOK, users)
}

// SelectedUsers retrieves a list of users with the given IDs.
// It authenticates the request using the provided token, calls the database
// to retrieve the users, and returns the result.
func (api *Api) SelectedUsers(c *gin.Context) {
	var requestBody struct {
		UserIds []string `json:"ids"`
	}

	if err := c.ShouldBindJSON(&requestBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON payload"})
		return
	}

	userIds := requestBody.UserIds
	user, err := api.GetUserFromToken(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	users, err := api.Database.getUsersByIds(user.ID, userIds)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, users)
}

func (api *Api) UsersPagination(c *gin.Context) {
	searchQuery := c.Query("q")
	// limitStr := c.Query("limit")
	pageStr := c.Query("page")
	pageSizeStr := c.Query("pageSize")
	user, err := api.GetUserFromToken(c)
	if err != nil {
		return
	}

	// Convert the limit, page, and pageSize parameters to integers
	// limit, _ := strconv.Atoi(limitStr)
	page, _ := strconv.Atoi(pageStr)
	pageSize, _ := strconv.Atoi(pageSizeStr)
	users := api.Database.allUsersWithPagination(user.ID, searchQuery, page, pageSize)
	c.JSON(http.StatusOK, users)
}

// OauthRedirect handles the OAuth redirect flow. It generates the authorization URL for the
// Google OAuth2 flow and returns it as a JSON response.
func (api *Api) OauthRedirect(c *gin.Context) {
	url := services.GoogleOAuthConfig.AuthCodeURL(services.OauthStateString)
	//c.Redirect(http.StatusTemporaryRedirect, "")
	c.JSON(http.StatusOK, gin.H{
		"redirect": url,
	})
}

// OauthCallBack handles the OAuth callback flow. It exchanges the authorization code for an access token,
// retrieves the user's Google profile information, creates or updates the user in the database, creates a
// social auth client record, updates the user's profile fields, and generates a JWT token for the user.

func (api *Api) OauthCallBack(c *gin.Context) {
	code := c.Query("code")
	platform := c.Query("platform")
	if code == "" {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "Missing authorization code"})
		return
	}

	token, err := services.GoogleOAuthConfig.Exchange(context.Background(), code)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to exchange authorization code for token"})
		return
	}

	googleUserInfo, err := services.GetUserInfo(token)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user info"})
		return
	}

	// user
	user, err := api.Database.OauthGetOrCreateUser(googleUserInfo.Email, googleUserInfo.GivenName)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	// social model
	err = api.Database.CreateSocialAuthClient("google", user.ID, googleUserInfo.ID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	// update profile fields
	profile := map[string]string{
		"first_name":   googleUserInfo.GivenName,
		"last_name":    googleUserInfo.FamilyName,
		"display_name": googleUserInfo.Name,
		//"avatar":       googleUserInfo.Picture,
		"username": googleUserInfo.GivenName,
	}

	for key, value := range profile {
		err := api.Database.updateProfile(user.ID, key, value)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}
	}

	// Create a new JWT token
	secret := []byte(os.Getenv("SECRET"))
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":  user.ID,
		"platform": platform,
		"exp":      time.Now().Local().Add(time.Minute * time.Duration(10)).Unix(),
		"nbf":      time.Now().Unix(),
	})

	// Sign and get the complete encoded JWT token as a string using the secret
	jwtTokenString, err := jwtToken.SignedString(secret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to sign JWT token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"version": api.Config.Get("apiVersion"),
		"step":    user.RegistrationStep,
		"user_id": user.ID,
		"token":   jwtTokenString,
	})
}
