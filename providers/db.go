package providers

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/imanimen/gAuth/models"
	"github.com/imanimen/gAuth/utils"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

// Domain errors surfaced by the database layer.
var (
	ErrUserNotFound    = errors.New("user not found")
	ErrProfileNotFound = errors.New("profile not found")
	ErrOTPNotFound     = errors.New("OTP record not found")
	ErrOTPExpired      = errors.New("OTP code expired")
	ErrUsernameTaken   = errors.New("username already exists")
	ErrCategoryExists  = errors.New("category already in the list")
	ErrCategoryMissing = errors.New("category not found in the list")
)

// IDatabase is the database access contract used by the API handlers.
type IDatabase interface {
	GetUserByID(id string) (*models.User, error)
	SendOTP(email string) (code string, expireAt string, err error)
	VerifyCode(email string, code string) (*models.User, error)
	UpdateUserRegistrationStep(userId string, step int) (int, error)
	UpdateUsername(user *models.User, username string) (*models.User, error)
	UpdateProfile(userId string, itemKey string, itemValue string) error
	IsUsernameUnique(username string, userID string) error
	DeleteProfile(userId string, itemKey string) error
	AddCategory(userId string, categoryId string) error
	DeleteCategory(userId string, categoryId string) error
	AllUsers(userId string, q string, limit int) []models.User
	GetUsersByIds(userId string, userIds []string) ([]models.User, error)
	FetchProfileByUserID(userId string) map[string]string
	AllUsersWithPagination(userId string, q string, page int, pageSize int) []models.User
	OauthGetOrCreateUser(email string, username string) (*models.User, error)
	CreateSocialAuthClient(provider string, userId string, providerUserId string) error
}

// Database is the Gorm implementation of IDatabase.
type Database struct {
	Connection *gorm.DB
}

// NewDB opens the production database connection described by the config.
func NewDB(config IConfig) (*gorm.DB, error) {
	db, err := gorm.Open(mysql.Open(config.DSN()), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("connecting database: %w", err)
	}
	return db, nil
}

// NewDatabase builds the IDatabase implementation on top of an existing
// connection and runs the model migrations.
func NewDatabase(db *gorm.DB) IDatabase {
	if err := db.AutoMigrate(
		&models.User{},
		&models.OTP{},
		&models.Profile{},
		&models.SocialAuth{},
	); err != nil {
		panic("database migration failed: " + err.Error())
	}
	return &Database{Connection: db}
}

// NewTestDatabase builds the IDatabase implementation on the given connection
// without running migrations, which the test harness manages manually.
func NewTestDatabase(db *gorm.DB) IDatabase {
	return &Database{Connection: db}
}

// GetUserByID retrieves a user from the database by ID and enriches it with
// the user's profile data.
func (d *Database) GetUserByID(id string) (*models.User, error) {
	var user models.User
	err := d.Connection.Where("id = ?", id).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	profiles := d.fetchProfilesForUserIDs([]string{user.ID})
	d.applyProfiles(&user, profiles[user.ID])
	return &user, nil
}

// SendOTP generates a new OTP for the given email. A user record is created
// on first contact. The previous OTP, if any, is replaced with a fresh code.
func (d *Database) SendOTP(email string) (string, string, error) {
	var user models.User
	err := d.Connection.Where("email = ?", email).First(&user).Error
	if err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return "", "", err
		}

		now := time.Now().Format(time.RFC3339)
		user = models.User{
			ID:               uuid.New().String(),
			Email:            email,
			Username:         "",
			EmailVerifiedAt:  "",
			RegistrationStep: models.FirstStep,
			CreatedAt:        now,
			UpdatedAt:        now,
		}
		if err := d.Connection.Create(&user).Error; err != nil {
			return "", "", err
		}
	}

	code := (&models.OTP{}).GenerateOTP()
	expirationTime := time.Now().Add(5 * time.Minute).Format(time.RFC3339)
	now := time.Now().Format(time.RFC3339)

	var otp models.OTP
	err = d.Connection.Where("user_id = ?", user.ID).First(&otp).Error
	switch {
	case err == nil:
		if err := d.Connection.Model(&otp).Updates(models.OTP{
			Code:         code,
			CodeExpireAt: expirationTime,
			UpdatedAt:    now,
		}).Error; err != nil {
			return "", "", err
		}
	case errors.Is(err, gorm.ErrRecordNotFound):
		otp = models.OTP{
			UserID:       user.ID,
			Email:        user.Email,
			PhoneNumber:  "",
			Code:         code,
			CodeExpireAt: expirationTime,
			CreatedAt:    now,
			UpdatedAt:    now,
		}
		if err := d.Connection.Create(&otp).Error; err != nil {
			return "", "", err
		}
	default:
		return "", "", err
	}

	return code, expirationTime, nil
}

// VerifyCode validates the OTP email/code pair, clears the code so it cannot
// be replayed, and moves the user's registration forward. Expired codes are
// rejected.
func (d *Database) VerifyCode(email, code string) (*models.User, error) {
	var otp models.OTP
	err := d.Connection.Where("email = ? AND code = ?", email, code).First(&otp).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrOTPNotFound
		}
		return nil, err
	}

	if expired, parseErr := isOTPExpired(otp.CodeExpireAt); parseErr != nil || expired {
		if parseErr != nil {
			return nil, parseErr
		}
		return nil, ErrOTPExpired
	}

	if err := d.Connection.Model(&otp).Updates(map[string]interface{}{
		"code":           nil,
		"code_expire_at": "",
		"updated_at":     time.Now().Format(time.RFC3339),
	}).Error; err != nil {
		return nil, err
	}

	user := &models.User{}
	if err := d.Connection.Where("id = ?", otp.UserID).First(user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	if user.RegistrationStep == models.FirstStep {
		if _, err := d.UpdateUserRegistrationStep(user.ID, models.SecondStep); err != nil {
			return nil, err
		}
		user.RegistrationStep = models.SecondStep
		user.EmailVerifiedAt = time.Now().Format(time.RFC3339)
	}

	return user, nil
}

// UpdateUserRegistrationStep persists a new registration step for the user.
func (d *Database) UpdateUserRegistrationStep(userID string, step int) (int, error) {
	var user models.User
	err := d.Connection.Where("id = ?", userID).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return 0, ErrUserNotFound
		}
		return 0, err
	}

	if user.RegistrationStep == step {
		return user.RegistrationStep, nil
	}

	user.RegistrationStep = step
	user.UpdatedAt = time.Now().Format(time.RFC3339)
	if err := d.Connection.Save(&user).Error; err != nil {
		return 0, err
	}
	return user.RegistrationStep, nil
}

// UpdateUsername updates the username for the given user and mirrors it into
// the user's profile.
func (d *Database) UpdateUsername(user *models.User, username string) (*models.User, error) {
	if err := d.IsUsernameUnique(username, user.ID); err != nil {
		return nil, err
	}

	user.Username = username
	user.UpdatedAt = time.Now().Format(time.RFC3339)
	if err := d.Connection.Save(user).Error; err != nil {
		return nil, err
	}

	if err := d.updateProfile(user.ID, models.KeyUsername, username); err != nil {
		return nil, err
	}
	return user, nil
}

// UpdateProfile creates or updates the profile key/value pair for the user.
func (d *Database) UpdateProfile(userId, itemKey, itemValue string) error {
	return d.updateProfile(userId, itemKey, itemValue)
}

func (d *Database) updateProfile(userId, itemKey, itemValue string) error {
	if itemValue == "" {
		return nil
	}

	var profile models.Profile
	result := d.Connection.Where("user_id = ? AND `key` = ?", userId, itemKey).First(&profile)
	switch {
	case result.Error == nil:
		profile.Value = itemValue
		profile.UpdatedAt = time.Now().Format(time.RFC3339)
		if err := d.Connection.Save(&profile).Error; err != nil {
			return err
		}
	case errors.Is(result.Error, gorm.ErrRecordNotFound):
		newProfile := models.Profile{
			UserId:    userId,
			Key:       itemKey,
			Value:     itemValue,
			CreatedAt: time.Now().Format(time.RFC3339),
			UpdatedAt: time.Now().Format(time.RFC3339),
		}
		if err := d.Connection.Create(&newProfile).Error; err != nil {
			return err
		}
	default:
		return result.Error
	}

	// Moving forward in the registration flow as profile data comes in.
	if user, err := d.GetUserByID(userId); err == nil {
		switch itemKey {
		case models.KeyUsername:
			if user.RegistrationStep == models.SecondStep {
				if _, err := d.UpdateUserRegistrationStep(userId, models.ThirdStep); err != nil {
					return err
				}
			}
		case models.KeyFavoriteCategories:
			if user.RegistrationStep == models.ThirdStep {
				if _, err := d.UpdateUserRegistrationStep(userId, models.FourthStep); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// FetchProfileByUserIDAndKey retrieves a single profile value.
func (d *Database) FetchProfileByUserIDAndKey(userID, itemKey string) string {
	var profile models.Profile
	result := d.Connection.Raw(
		"SELECT user_id, `key`, value FROM profiles WHERE user_id = ? AND `key` = ? LIMIT 1",
		userID, itemKey,
	).Scan(&profile)
	if result.Error != nil {
		return ""
	}
	return profile.Value
}

// IsUsernameUnique checks that no other user already owns the username.
func (d *Database) IsUsernameUnique(username, userID string) error {
	var existingUser models.User
	if err := d.Connection.Where("username = ? AND id != ?", username, userID).First(&existingUser).Error; err == nil {
		return ErrUsernameTaken
	}
	return nil
}

// DeleteProfile removes the profile key for the user. Deleting a missing key
// is not an error.
func (d *Database) DeleteProfile(userId, itemKey string) error {
	var profile models.Profile
	result := d.Connection.Where("user_id = ? AND `key` = ?", userId, itemKey).First(&profile)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil
		}
		return result.Error
	}
	return d.Connection.Delete(&profile).Error
}

// AddCategory appends a category ID to the user's favorite categories list.
func (d *Database) AddCategory(userId, categoryId string) error {
	if categoryId == "" {
		return errors.New("category_id is required")
	}

	profile, err := d.getCategoryProfile(userId)
	if err != nil {
		return err
	}

	for _, id := range splitCategories(profile.Value) {
		if id == categoryId {
			return ErrCategoryExists
		}
	}
	profile.Value = strings.Join(append(splitCategories(profile.Value), categoryId), ",")

	return d.Connection.Model(&profile).
		Where("user_id = ? AND `key` = ?", userId, models.KeyFavoriteCategories).
		Updates(map[string]interface{}{
			"value":      profile.Value,
			"updated_at": time.Now().Format(time.RFC3339),
		}).Error
}

// DeleteCategory removes a category ID from the user's favorite categories
// list. Removing a category that is not in the list is an error.
func (d *Database) DeleteCategory(userId, categoryId string) error {
	if categoryId == "" {
		return errors.New("category_id is required")
	}

	profile, err := d.getCategoryProfile(userId)
	if err != nil {
		return err
	}

	categories := splitCategories(profile.Value)
	kept := make([]string, 0, len(categories))
	removed := false
	for _, id := range categories {
		if id == categoryId {
			removed = true
			continue
		}
		kept = append(kept, id)
	}
	if !removed {
		return ErrCategoryMissing
	}
	profile.Value = strings.Join(kept, ",")

	return d.Connection.Model(&profile).
		Where("user_id = ? AND `key` = ?", userId, models.KeyFavoriteCategories).
		Updates(map[string]interface{}{
			"value":      profile.Value,
			"updated_at": time.Now().Format(time.RFC3339),
		}).Error
}

// AllUsers lists users other than the given one, optionally filtered by a
// search query and limited, enriched with profile data.
func (d *Database) AllUsers(userId string, q string, limit int) []models.User {
	users, err := d.listUsers(userId, q, limit, 0)
	if err != nil {
		return nil
	}
	return users
}

// AllUsersWithPagination lists users other than the given one with page/pageSize
// pagination and optional search query, enriched with profile data.
func (d *Database) AllUsersWithPagination(userId string, q string, page, pageSize int) []models.User {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		return []models.User{}
	}

	users, err := d.listUsers(userId, q, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil
	}
	return users
}

func (d *Database) listUsers(userId, q string, limit, offset int) ([]models.User, error) {
	query := d.Connection.Table("users").
		Joins("LEFT JOIN profiles as profiles_display_name ON profiles_display_name.user_id = users.id AND profiles_display_name.key = ?", models.KeyDisplayName).
		Joins("LEFT JOIN profiles as profiles_about ON profiles_about.user_id = users.id AND profiles_about.key = ?", models.KeyAbout).
		Where("users.id != ?", userId).
		Order("users.created_at desc")

	if q != "" {
		search := "%" + q + "%"
		query = query.Where("users.username LIKE ? OR profiles_display_name.value LIKE ? OR profiles_about.value LIKE ?", search, search, search)
	}
	if limit > 0 {
		query = query.Limit(limit)
	}
	if offset > 0 {
		query = query.Offset(offset)
	}

	var users []models.User
	if err := query.Find(&users).Error; err != nil {
		return nil, err
	}
	d.applyProfilesToUsers(users)
	return users, nil
}

// GetUsersByIds retrieves the users matching the given IDs, excluding the
// requesting user, enriched with profile data.
func (d *Database) GetUsersByIds(userId string, userIds []string) ([]models.User, error) {
	var users []models.User
	if len(userIds) == 0 {
		return users, nil
	}

	query := d.Connection.Table("users").
		Joins("LEFT JOIN profiles as profiles_display_name ON profiles_display_name.user_id = users.id AND profiles_display_name.key = ?", models.KeyDisplayName).
		Joins("LEFT JOIN profiles as profiles_about ON profiles_about.user_id = users.id AND profiles_about.key = ?", models.KeyAbout).
		Where("users.id != ? AND users.id IN (?)", userId, userIds).
		Order("users.created_at desc")

	if err := query.Find(&users).Error; err != nil {
		return nil, err
	}
	d.applyProfilesToUsers(users)
	return users, nil
}

// FetchProfileByUserID returns the user's profile as a key/value map.
func (d *Database) FetchProfileByUserID(userId string) map[string]string {
	profiles := make(map[string]string)
	var rows []models.Profile
	if err := d.Connection.Where("user_id = ?", userId).Find(&rows).Error; err != nil {
		return profiles
	}
	for _, p := range rows {
		profiles[p.Key] = p.Value
	}
	return profiles
}

// OauthGetOrCreateUser returns the user for the given email or creates one
// when it does not exist yet.
func (d *Database) OauthGetOrCreateUser(email, username string) (*models.User, error) {
	var user models.User
	err := d.Connection.Where("email = ?", email).First(&user).Error
	if err == nil {
		return &user, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	now := time.Now().Format(time.RFC3339)
	newUser := models.User{
		ID:               uuid.New().String(),
		Email:            email,
		Username:         username,
		EmailVerifiedAt:  now,
		RegistrationStep: models.SecondStep,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if err := d.Connection.Create(&newUser).Error; err != nil {
		return nil, err
	}
	return &newUser, nil
}

// CreateSocialAuthClient records a social login binding for the user. The
// binding is created once per provider.
func (d *Database) CreateSocialAuthClient(provider, userId, providerUserId string) error {
	var social models.SocialAuth
	result := d.Connection.Where("user_id = ? AND provider = ?", userId, provider).First(&social)
	switch {
	case result.Error == nil:
		return nil
	case errors.Is(result.Error, gorm.ErrRecordNotFound):
		record := models.SocialAuth{
			UserId:         userId,
			Provider:       provider,
			ProviderUserID: providerUserId,
			CreatedAt:      time.Now().Format(time.RFC3339),
		}
		return d.Connection.Create(&record).Error
	default:
		return result.Error
	}
}

// --- profile enrichment helpers ---

// fetchProfilesForUserIDs loads all profile rows for the given user ids in a
// single query and groups them per user.
func (d *Database) fetchProfilesForUserIDs(userIDs []string) map[string]map[string]string {
	profiles := make(map[string]map[string]string, len(userIDs))
	if len(userIDs) == 0 {
		return profiles
	}

	var rows []models.Profile
	if err := d.Connection.Where("user_id IN (?)", userIDs).Find(&rows).Error; err != nil {
		return profiles
	}
	for _, row := range rows {
		userProfiles, ok := profiles[row.UserId]
		if !ok {
			userProfiles = make(map[string]string)
			profiles[row.UserId] = userProfiles
		}
		userProfiles[row.Key] = row.Value
	}
	return profiles
}

// applyProfiles enriches a user with its profile map, resolving file based
// values through the file service.
func (d *Database) applyProfiles(user *models.User, profiles map[string]string) {
	user.Avatar = d.resolveFile(profiles[models.KeyAvatar])
	user.Cover = d.resolveFile(profiles[models.KeyCover])
	user.DisplayName = profiles[models.KeyDisplayName]
	user.FirstName = profiles[models.KeyFirstName]
	user.LastName = profiles[models.KeyLastName]
	user.Birthdate = profiles[models.KeyBirthday]
	user.Age = profiles[models.KeyAge]
	user.About = profiles[models.KeyAbout]
	user.Gender = profiles[models.KeyGender]
	user.FavoriteCategories = profiles[models.KeyFavoriteCategories]
}

// applyProfilesToUsers enriches all users in one go, using a single profile
// query instead of one per user per key.
func (d *Database) applyProfilesToUsers(users []models.User) {
	if len(users) == 0 {
		return
	}
	ids := make([]string, len(users))
	for i := range users {
		ids[i] = users[i].ID
	}
	profiles := d.fetchProfilesForUserIDs(ids)
	for i := range users {
		d.applyProfiles(&users[i], profiles[users[i].ID])
	}
}

// resolveFile maps a stored file ID to its public URL, tolerating lookup
// failures by returning an empty string.
func (d *Database) resolveFile(fileID string) string {
	url, err := utils.GetFilePath(fileID)
	if err != nil || url == "" {
		return ""
	}
	return url
}

func (d *Database) getCategoryProfile(userId string) (models.Profile, error) {
	var profile models.Profile
	err := d.Connection.Where("user_id = ? AND `key` = ?", userId, models.KeyFavoriteCategories).First(&profile).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return profile, ErrProfileNotFound
		}
		return profile, err
	}
	return profile, nil
}

func splitCategories(value string) []string {
	if value == "" {
		return nil
	}
	return strings.Split(value, ",")
}

func isOTPExpired(expireAt string) (bool, error) {
	if expireAt == "" {
		return true, nil
	}
	expireTime, err := time.Parse(time.RFC3339, expireAt)
	if err != nil {
		return false, fmt.Errorf("parsing OTP expiration: %w", err)
	}
	return time.Now().After(expireTime), nil
}
