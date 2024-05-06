package providers

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"git.dyneemadev.com/micro-services/go-auth/models"
	"github.com/google/uuid"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

type IDatabase interface {
	getUserByID(id string) (*models.User, error)
	sendOTP(email string) (string, string, error)
	verifyCode(email, code string) (*models.User, error)
	updateUserRegistrationStep(userId string, step int) (int, error)
	updateUsername(user *models.User, username string) (*models.User, error)
	updateProfile(userId, itemKey, itemValue string) error
	isUsernameUnique(username, userID string) error
	deleteProfile(userId, itemKey string) error
	addCategory(userId, categoryId string) error
	deleteCategory(userId, categoryId string) error
	allUsers(userId string, q string, limit int) []models.User
	getUsersByIds(userId string, userIds []string) ([]models.User, error)
	FetchProfileByUserID(userId string) map[string]string
	allUsersWithPagination(userId string, q string, page, pageSize int) []models.User
	OauthGetOrCreateUser(email string, username string) (*models.User, error)
	CreateSocialAuthClient(provider, userId, providerUserId string) error
	CountData(model interface{}) int64
}

type Database struct {
	Connection *gorm.DB
	Config     IConfig
}

// NewDatabase creates a new Database instance with a connection to the
// database using the provided config. It runs migrations for the User,
// OTP and Profile models.
func NewDatabase(config IConfig) IDatabase {
	dsn := config.Get("dsn")
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("Error connecting db")
	}

	db.AutoMigrate(&models.User{})
	db.AutoMigrate(&models.OTP{})
	db.AutoMigrate(&models.Profile{})
	db.AutoMigrate(&models.SocialAuth{})

	return &Database{
		Connection: db,
		Config:     config,
	}
}

func (database *Database) CountData(model interface{}) int64 {
	var totalDataCount int64
	database.Connection.Model(model).Count(&totalDataCount)
	return totalDataCount
}

// getUserByID retrieves a user from the database by ID.
// It returns a pointer to a User model and an error.
// The ID is passed in as a string.
// It first queries the database by ID and returns an error if not found.
// It then populates the Avatar and Cover fields by fetching the user's profile.
// Returns the User or an error.
func (database *Database) getUserByID(id string) (*models.User, error) {
	var user models.User
	err := database.Connection.Where("id = ?", id).First(&user).Error
	if err != nil {
		if errors.Is(gorm.ErrRecordNotFound, err) {
			return nil, fmt.Errorf("record not found")
		}
		return nil, err
	}
	user.Gender = database.FetchProfileByUserIDAndKey(user.ID, models.KeyGender)
	user.Avatar = user.GetAvatar(database.FetchProfileByUserIDAndKey(user.ID, models.KeyAvatar))
	user.Cover = user.GetCover(database.FetchProfileByUserIDAndKey(user.ID, models.KeyCover))
	user.DisplayName = database.FetchProfileByUserIDAndKey(user.ID, models.KeyDisplayName)
	user.About = database.FetchProfileByUserIDAndKey(user.ID, models.KeyAbout)
	user.FavoriteCategories = database.FetchProfileByUserIDAndKey(user.ID, models.KeyFavoriteCategories)
	user.Birthdate = database.FetchProfileByUserIDAndKey(user.ID, models.KeyBirthday)
	user.Age = database.FetchProfileByUserIDAndKey(user.ID, models.KeyAge)
	user.FirstName = database.FetchProfileByUserIDAndKey(user.ID, models.KeyFirstName)
	user.LastName = database.FetchProfileByUserIDAndKey(user.ID, models.KeyLastName)

	return &user, nil
}

// sendOTP generates a new OTP code for the given email address.
// It first checks if a user exists for that email. If not,
// it creates a new user. Then it generates a new OTP code and expiration time, saves it to the database,
// and returns the code and expiration time. If a user already exists, it just generates a new code.
func (database *Database) sendOTP(email string) (string, string, error) {
	var user models.User
	err := database.Connection.Where("email = ?", email).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			newUser := models.User{
				ID:               uuid.New().String(),
				Email:            email,
				Username:         "",
				EmailVerifiedAt:  "",
				RegistrationStep: models.FirstStep,
				CreatedAt:        time.Now().Format(time.RFC3339),
				UpdatedAt:        time.Now().Format(time.RFC3339),
			}

			if err := database.Connection.Create(&newUser).Error; err != nil {
				return "", "", err
			}

			user = newUser
		} else {
			return "", "", err
		}
	}

	var otp models.OTP
	err = database.Connection.Where("user_id = ?", user.ID).First(&otp).Error
	if err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return "", "", err
		}
	}

	if otp.ID == 0 {
		newCode := otp.GenerateOTP()
		expirationTime := time.Now().Add(time.Minute * 5).Format(time.RFC3339)

		otp = models.OTP{
			UserID:       user.ID,
			Email:        user.Email,
			PhoneNumber:  "", // Add phone number if needed
			Code:         newCode,
			CodeExpireAt: expirationTime,
			CreatedAt:    time.Now().Format(time.RFC3339),
			UpdatedAt:    time.Now().Format(time.RFC3339),
		}

		if err := database.Connection.Create(&otp).Error; err != nil {
			return "", "", err
		}

		return newCode, expirationTime, nil
	}

	newCode := otp.GenerateOTP()
	expirationTime := time.Now().Add(time.Minute * 5).Format(time.RFC3339)

	if err := database.Connection.Model(&otp).Updates(models.OTP{Code: newCode, CodeExpireAt: expirationTime}).Error; err != nil {
		return "", "", err
	}

	return newCode, expirationTime, nil
}

func (database *Database) OauthGetOrCreateUser(email string, username string) (*models.User, error) {
	var user models.User
	err := database.Connection.Where("email = ?", email).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			newUser := models.User{
				ID:               uuid.New().String(),
				Email:            email,
				Username:         username,
				EmailVerifiedAt:  time.Now().Format(time.RFC3339),
				RegistrationStep: models.SecondStep,
				CreatedAt:        time.Now().Format(time.RFC3339),
				UpdatedAt:        time.Now().Format(time.RFC3339),
			}

			var otp models.OTP
			err = database.Connection.Where("user_id = ?", newUser.ID).First(&otp).Error
			if err != nil {
				if !errors.Is(err, gorm.ErrRecordNotFound) {
					return nil, err
				}
			}

			if otp.ID == 0 {
				expirationTime := time.Now().Add(time.Minute * 5).Format(time.RFC3339)

				otp = models.OTP{
					UserID:       newUser.ID,
					Email:        newUser.Email,
					PhoneNumber:  "", // Add phone number if needed
					Code:         "",
					CodeExpireAt: expirationTime,
					CreatedAt:    time.Now().Format(time.RFC3339),
					UpdatedAt:    time.Now().Format(time.RFC3339),
				}

				if err := database.Connection.Create(&otp).Error; err != nil {
					return nil, err
				}
			}

			if err := database.Connection.Create(&newUser).Error; err != nil {
				return nil, err
			}

			return &newUser, nil
		}
		return nil, err
	}
	return &user, nil
}

// verifyCode verifies an OTP code by retrieving the OTP record with the
// provided email and code. Its nulls out the code and expiration in the OTP
// record, retrieves the user record, updates the user's registration step
// if needed, reloads the user object, and updates the user's email_verified_at
// field. It returns the verified user record. Any errors are returned.
func (database *Database) verifyCode(email, code string) (*models.User, error) {
	// retrieve OTP record
	var otp models.OTP
	if err := database.Connection.Where("email = ? AND code = ?", email, code).First(&otp).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("OTP record not found")
		}
		return nil, err
	}

	// update the OTP record with null values for Code and CodeExpireAt
	if err := database.Connection.Model(&otp).Update("code", nil).Error; err != nil {
		return nil, err
	}

	// retrieve user information
	user := &models.User{}
	if err := database.Connection.Where("id = ?", otp.UserID).First(user).Error; err != nil {
		return nil, err
	}

	// update the user's registration step to SECOND_STEP if it is currently at FIRST_STEP
	if user.RegistrationStep == models.FirstStep {
		if _, err := database.updateUserRegistrationStep(otp.UserID, models.SecondStep); err != nil {
			return nil, err
		}

		// Reload the user object to reflect the updated values
		if err := database.Connection.Where("id = ?", otp.UserID).First(user).Error; err != nil {
			return nil, err
		}

		// update the user's email_verified_at field with the current time
		if err := database.Connection.Model(&models.User{}).Where("id = ?", otp.UserID).Update("email_verified_at", time.Now().Format(time.RFC3339)).Error; err != nil {
			return nil, err
		}
	}

	return user, nil
}

// updateUserRegistrationStep updates the registration step for the user with the given ID.
// It returns the updated registration step value, or an error if the update fails.
func (database *Database) updateUserRegistrationStep(userID string, step int) (int, error) {
	var user models.User
	err := database.Connection.Where("id = ?", userID).First(&user).Error
	if err != nil {
		if errors.Is(gorm.ErrRecordNotFound, err) {
			return 0, errors.New("user not found")
		}
		return 0, err
	}

	user.RegistrationStep = step
	user.UpdatedAt = time.Now().Format(time.RFC3339)
	if err := database.Connection.Save(&user).Error; err != nil {
		return 0, err
	}

	return user.RegistrationStep, nil
}

// updateUsername updates the username for the given user, saving the updated user
// object back to the database. It also updates the username in the user's profile.
// Returns the updated user object, or an error if the update fails.
func (database *Database) updateUsername(user *models.User, username string) (*models.User, error) {
	// Check if the new username is unique
	if err := database.isUsernameUnique(username, user.ID); err != nil {
		return nil, err
	}

	user.Username = username
	user.UpdatedAt = time.Now().Format(time.RFC3339)
	if err := database.Connection.Save(&user).Error; err != nil {
		return nil, err
	}
	err := database.updateProfile(user.ID, models.KeyUsername, username)
	if err != nil {
		return nil, err
	}

	return user, nil
}

// updateProfile updates the value for the given profile item key for the user.
// It first checks if a profile record exists for that user ID and key.
// If not, it will create a new record if the itemValue is not empty.
// If a record exists, it updates the value and timestamps.
func (database *Database) updateProfile(userId string, itemKey string, itemValue string) error {
	var profile models.Profile
	result := database.Connection.Where("user_id = ? AND `key` = ?", userId, itemKey).First(&profile)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			if itemValue != "" {
				newProfile := models.Profile{
					UserId:    userId,
					Key:       itemKey,
					Value:     itemValue,
					CreatedAt: time.Now().Format(time.RFC3339),
					UpdatedAt: time.Now().Format(time.RFC3339),
				}
				if err := database.Connection.Create(&newProfile).Error; err != nil {
					return err
				}
			}
		} else {
			return result.Error
		}
	} else {
		if itemValue != "" {
			profile.Value = itemValue
			profile.UpdatedAt = time.Now().Format(time.RFC3339)
			if profile.ID == 0 {
				// Check if the profile has an ID (indicating it's a new record)
				if err := database.Connection.Create(&profile).Error; err != nil {
					return err
				}
			} else {
				if err := database.Connection.Save(&profile).Error; err != nil {
					return err
				}
			}
			if itemKey == models.KeyUsername {
				user, err := database.getUserByID(userId)
				if err != nil {
					return err
				}

				if user.RegistrationStep == models.SecondStep {
					_, err := database.updateUserRegistrationStep(userId, models.ThirdStep)
					if err != nil {
						return err
					}
				}
			}
			if itemKey == models.KeyFavoriteCategories {
				u, err := database.getUserByID(userId)
				if err != nil {
					return err
				}

				if u.RegistrationStep == models.ThirdStep {
					_, err := database.updateUserRegistrationStep(userId, models.FourthStep)
					if err != nil {
						return err
					}
				}
			}
		} else {
			return nil
		}
	}

	return nil
}

// FetchProfileByUserIDAndKey retrieves the profile value for the given user ID
// and profile key from the database. Returns an empty string if no matching
// profile is found.
func (database *Database) FetchProfileByUserIDAndKey(userID string, itemKey string) string {
	var profile models.Profile
	query := "SELECT value FROM profiles WHERE user_id = ? AND `key` = ? LIMIT 1"
	result := database.Connection.Raw(query, userID, itemKey).Scan(&profile)
	if result.Error != nil {
		return ""
	}
	return profile.Value
}

// isUsernameUnique checks if the given username already exists for a different user ID.
// Returns nil if the username is unique, or an error if it already exists.
func (database *Database) isUsernameUnique(username string, userID string) error {
	var existingUser models.User
	if err := database.Connection.Where("username = ? AND id != ?", username, userID).First(&existingUser).Error; err == nil {
		return errors.New("username already exists")
	}
	return nil
}

// deleteProfile deletes the profile record for the given user ID and profile
// key from the database. It first queries for the profile record. If not
// found, it returns nil. If found, it deletes the record and returns any
// errors.
func (database *Database) deleteProfile(userId string, itemKey string) error {
	var profile models.Profile
	result := database.Connection.Where("user_id = ? AND `key` = ?", userId, itemKey).First(&profile)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			// Profile record not found, no action needed
			return nil
		} else {
			// Error occurred while querying for the profile record
			return result.Error
		}
	}

	// Delete the profile record
	if err := database.Connection.Delete(&profile).Error; err != nil {
		return err
	}

	return nil
}

// addCategory adds the given category ID to the user's list of favorite categories.
// It first checks if the category ID is provided, returns an error if not.
// Then it gets the user's profile, extracts the existing category IDs, checks if
// the given ID already exists, and appends the new ID if not. Finally, it updates
// the profile with the new category list. Returns any errors encountered.
func (database *Database) addCategory(userId string, categoryId string) error {
	// Check if the category ID is provided
	if categoryId == "" {
		return errors.New("category_id is required")
	}

	// Get the user profile
	var profile models.Profile
	result := database.Connection.Where("user_id = ? AND `key` = ?", userId, "favorite_categories").First(&profile)
	if result.Error != nil {
		// Handle error or create a new profile if not found
		return result.Error
	}

	// Extract existing category IDs
	categoriesID := strings.Split(profile.Value, ",")

	// Check if the category is already in the list
	for _, id := range categoriesID {
		if id == categoryId {
			return errors.New("category already in the list")
		}
	}

	// Add the new category ID
	categoriesID = append(categoriesID, categoryId)

	// Update the profile with the new category list
	updatedCategories := strings.Join(categoriesID, ",")
	result = database.Connection.Model(&profile).Where("user_id = ? AND `key` = ?", userId, "favorite_categories").Update("value", updatedCategories)
	if result.Error != nil {
		return result.Error
	}

	return nil
}

// deleteCategory removes the provided categoryId from the
// comma-separated list of favorite category IDs stored in
// the user's profile. It returns an error if the categoryId
// is not found in the existing list.
func (database *Database) deleteCategory(userId string, categoryId string) error {
	// Check if the category ID is provided
	if categoryId == "" {
		return errors.New("category_id is required")
	}

	// Get the user profile
	var profile models.Profile
	result := database.Connection.Where("user_id = ? AND `key` = ?", userId, "favorite_categories").First(&profile)
	if result.Error != nil {
		// Handle error if profile not found
		return result.Error
	}

	// Extract existing category IDs
	categoriesID := strings.Split(profile.Value, ",")

	// Check if the category is in the list
	found := false
	for i, id := range categoriesID {
		if id == categoryId {
			found = true
			// Remove the category from the list
			categoriesID = append(categoriesID[:i], categoriesID[i+1:]...)
			break
		}
	}

	if !found {
		return errors.New("category not found in the list")
	}

	// Update the profile with the updated category list
	updatedCategories := strings.Join(categoriesID, ",")
	result = database.Connection.Model(&profile).Where("user_id = ? AND `key` = ?", userId, "favorite_categories").Update("value", updatedCategories)
	if result.Error != nil {
		return result.Error
	}

	return nil
}

// allUsers returns a slice of all User models in the database, except for
// the provided userId. It joins additional profile data like display
// name, avatar, etc. and applies search filtering if a search query is
// provided.
func (database *Database) allUsers(userId string, q string, limit int) []models.User {
	var users []models.User

	query := database.Connection.Table("users").
		Select("users.*, profiles_display_name.value as display_name, profiles_about.value as about").
		Joins("LEFT JOIN profiles as profiles_display_name ON profiles_display_name.user_id = users.id AND profiles_display_name.key = ?", models.KeyDisplayName).
		Joins("LEFT JOIN profiles as profiles_about ON profiles_about.user_id = users.id AND profiles_about.key = ?", models.KeyAbout).
		Where("users.id != ?", userId)

	if q != "" {
		query = query.Where("users.username LIKE ? OR profiles_display_name.value LIKE ? OR profiles_about.value LIKE ?", "%"+q+"%", "%"+q+"%", "%"+q+"%")
	}

	if limit > 0 {
		query = query.Limit(limit)
	}

	query.Order("users.created_at desc").Find(&users)
	for i := range users {
		users[i].Avatar = users[i].GetAvatar(database.FetchProfileByUserIDAndKey(users[i].ID, models.KeyAvatar))
		users[i].Cover = users[i].GetCover(database.FetchProfileByUserIDAndKey(users[i].ID, models.KeyCover))
		users[i].DisplayName = database.FetchProfileByUserIDAndKey(users[i].ID, models.KeyDisplayName)
		users[i].About = database.FetchProfileByUserIDAndKey(users[i].ID, models.KeyAbout)
		users[i].FavoriteCategories = database.FetchProfileByUserIDAndKey(users[i].ID, models.KeyFavoriteCategories)
	}

	return users
}

// getUsersByIds retrieves a list of User models by their IDs, excluding
// the given user ID and any users in the blockedIds list. It joins additional
// profile data like display name and about text.
func (database *Database) getUsersByIds(userId string, userIds []string) ([]models.User, error) {
	var users []models.User

	if len(userIds) == 0 {
		return users, nil
	}

	query := database.Connection.Table("users").
		Select("users.*, profiles_display_name.value as display_name, profiles_about.value as about").
		Joins("LEFT JOIN profiles as profiles_display_name ON profiles_display_name.user_id = users.id AND profiles_display_name.key = ?", models.KeyDisplayName).
		Joins("LEFT JOIN profiles as profiles_about ON profiles_about.user_id = users.id AND profiles_about.key = ?", models.KeyAbout).
		Where("users.id != ? AND users.id IN (?)", userId, userIds)

	if err := query.Find(&users).Error; err != nil {
		return nil, err
	}

	query.Order("users.created_at desc").Find(&users)
	for i := range users {
		users[i].Avatar = users[i].GetAvatar(database.FetchProfileByUserIDAndKey(users[i].ID, models.KeyAvatar))
		users[i].Cover = users[i].GetCover(database.FetchProfileByUserIDAndKey(users[i].ID, models.KeyCover))
		users[i].DisplayName = database.FetchProfileByUserIDAndKey(users[i].ID, models.KeyDisplayName)
		users[i].About = database.FetchProfileByUserIDAndKey(users[i].ID, models.KeyAbout)
		users[i].FavoriteCategories = database.FetchProfileByUserIDAndKey(users[i].ID, models.KeyFavoriteCategories)
	}

	return users, nil
}

// FetchProfileByUserID retrieves the profile data for the given user ID from
// the database. It returns a map of profile keys to values.
func (database *Database) FetchProfileByUserID(userId string) map[string]string {
	profile := make(map[string]string)

	rows, err := database.Connection.Table("profiles").
		Select("key, value"). // TODO: syntax error check
		Where("user_id = ?", userId).
		Rows()
	if err != nil {
		// Handle the error appropriately
		// For now, let's return an empty map
		return profile
	}
	defer rows.Close()

	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			// Handle the error, but continue processing other rows
			continue
		}
		profile[key] = value
	}

	if err := rows.Err(); err != nil {
		// Handle the error, but return the partially populated profile
		return profile
	}

	return profile
}

func (database *Database) allUsersWithPagination(userId string, q string, page, pageSize int) []models.User {
	var users []models.User

	query := database.Connection.Table("users").
		Select("users.*, profiles_display_name.value as display_name, profiles_about.value as about").
		Joins("LEFT JOIN profiles as profiles_display_name ON profiles_display_name.user_id = users.id AND profiles_display_name.key = ?", models.KeyDisplayName).
		Joins("LEFT JOIN profiles as profiles_about ON profiles_about.user_id = users.id AND profiles_about.key = ?", models.KeyAbout).
		Where("users.id != ?", userId)

	if q != "" {
		query = query.Where("users.username LIKE ? OR profiles_display_name.value LIKE ? OR profiles_about.value LIKE ?", "%"+q+"%", "%"+q+"%", "%"+q+"%")
	}

	offset := (page - 1) * pageSize
	query = query.Offset(offset).Limit(pageSize)

	query.Order("users.created_at desc").Find(&users)
	for i := range users {
		users[i].Avatar = users[i].GetAvatar(database.FetchProfileByUserIDAndKey(users[i].ID, models.KeyAvatar))
		users[i].Cover = users[i].GetCover(database.FetchProfileByUserIDAndKey(users[i].ID, models.KeyCover))
		users[i].DisplayName = database.FetchProfileByUserIDAndKey(users[i].ID, models.KeyDisplayName)
		users[i].About = database.FetchProfileByUserIDAndKey(users[i].ID, models.KeyAbout)
		users[i].FavoriteCategories = database.FetchProfileByUserIDAndKey(users[i].ID, models.KeyFavoriteCategories)
	}

	return users
}

// CreateSocialAuthClient creates a new social authentication record for the given provider and user ID.
// If a record already exists for the given user ID and provider, it returns without creating a new record.
// If an error occurs while querying for the existing record, the error is returned.
func (database *Database) CreateSocialAuthClient(provider, userId, providerUserId string) error {
	var social models.SocialAuth
	result := database.Connection.Where("user_id = ? AND `provider` = ?", userId, provider).First(&social)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			record := &models.SocialAuth{
				UserId:         userId,
				Provider:       provider,
				ProviderUserID: providerUserId,
				CreatedAt:      time.Now().Format(time.RFC3339),
			}
			fmt.Println(providerUserId)
			if err := database.Connection.Create(&record).Error; err != nil {
				return err
			}
			return nil
		} else {
			// Error occurred while querying for the profile record
			return result.Error
		}
	}
	return nil
}
