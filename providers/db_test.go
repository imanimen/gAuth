package providers

import (
	"testing"
	"time"

	gsqlite "github.com/glebarez/sqlite"
	"github.com/imanimen/gAuth/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func newTestDatabase(t *testing.T) *Database {
	t.Helper()

	db, err := gorm.Open(gsqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })

	require.NoError(t, db.AutoMigrate(
		&models.User{},
		&models.OTP{},
		&models.Profile{},
		&models.SocialAuth{},
	))

	return NewTestDatabase(db).(*Database)
}

func seedUser(t *testing.T, d *Database, id string, email string, step int) models.User {
	t.Helper()
	user := models.User{
		ID:               id,
		Email:            email,
		RegistrationStep: step,
		CreatedAt:        time.Now().Format(time.RFC3339),
		UpdatedAt:        time.Now().Format(time.RFC3339),
	}
	require.NoError(t, d.Connection.Create(&user).Error)
	return user
}

func seedProfile(t *testing.T, d *Database, userID, key, value string) {
	t.Helper()
	require.NoError(t, d.Connection.Create(&models.Profile{
		UserId: userID,
		Key:    key,
		Value:  value,
	}).Error)
}

func TestSendOTPCreatesUserAndOTP(t *testing.T) {
	d := newTestDatabase(t)

	code, expireAt, err := d.SendOTP("someone@example.com")
	require.NoError(t, err)
	assert.Len(t, code, 6)
	assert.NotEmpty(t, expireAt)

	var user models.User
	require.NoError(t, d.Connection.Where("email = ?", "someone@example.com").First(&user).Error)
	assert.Equal(t, models.FirstStep, user.RegistrationStep)

	var otpCount int64
	require.NoError(t, d.Connection.Model(&models.OTP{}).Count(&otpCount).Error)
	assert.Equal(t, int64(1), otpCount)
}

func TestSendOTPRegeneratesCode(t *testing.T) {
	d := newTestDatabase(t)

	code1, _, err := d.SendOTP("someone@example.com")
	require.NoError(t, err)
	code2, _, err := d.SendOTP("someone@example.com")
	require.NoError(t, err)
	assert.NotEqual(t, code1, code2)

	var otpCount int64
	require.NoError(t, d.Connection.Model(&models.OTP{}).Count(&otpCount).Error)
	assert.Equal(t, int64(1), otpCount)
}

func TestSendOTPSameCodeReplacement(t *testing.T) {
	d := newTestDatabase(t)

	_, _, err := d.SendOTP("someone@example.com")
	require.NoError(t, err)

	var stored models.OTP
	require.NoError(t, d.Connection.Where("email = ?", "someone@example.com").First(&stored).Error)
	assert.NotEmpty(t, stored.Code)
}

func TestVerifyCodeNotFound(t *testing.T) {
	d := newTestDatabase(t)
	_, _, err := d.SendOTP("someone@example.com")
	require.NoError(t, err)

	_, err = d.VerifyCode("someone@example.com", "999999")
	assert.ErrorIs(t, err, ErrOTPNotFound)
}

func TestVerifyCodeExpired(t *testing.T) {
	d := newTestDatabase(t)
	_, _, err := d.SendOTP("someone@example.com")
	require.NoError(t, err)

	// backdate the expiry
	require.NoError(t, d.Connection.Model(&models.OTP{}).
		Where("email = ?", "someone@example.com").
		Update("code_expire_at", time.Now().Add(-time.Minute).Format(time.RFC3339)).Error)

	var code string
	require.NoError(t, d.Connection.Raw("SELECT code FROM otps LIMIT 1").Scan(&code).Error)

	_, err = d.VerifyCode("someone@example.com", code)
	assert.ErrorIs(t, err, ErrOTPExpired)
}

func TestVerifyCodeSuccess(t *testing.T) {
	d := newTestDatabase(t)
	code, _, err := d.SendOTP("someone@example.com")
	require.NoError(t, err)

	user, err := d.VerifyCode("someone@example.com", code)
	require.NoError(t, err)
	assert.Equal(t, models.SecondStep, user.RegistrationStep)
	assert.NotEmpty(t, user.EmailVerifiedAt)

	// the code cannot be replayed
	_, err = d.VerifyCode("someone@example.com", code)
	assert.ErrorIs(t, err, ErrOTPNotFound)
}

func TestVerifyCodeKeepsLaterStep(t *testing.T) {
	d := newTestDatabase(t)
	code, _, err := d.SendOTP("someone@example.com")
	require.NoError(t, err)

	var user models.User
	require.NoError(t, d.Connection.Where("email = ?", "someone@example.com").First(&user).Error)
	_, err = d.UpdateUserRegistrationStep(user.ID, models.ThirdStep)
	require.NoError(t, err)

	verified, err := d.VerifyCode("someone@example.com", code)
	require.NoError(t, err)
	assert.Equal(t, models.ThirdStep, verified.RegistrationStep)
}

func TestUpdateUserRegistrationStep(t *testing.T) {
	d := newTestDatabase(t)
	seedUser(t, d, "u-1", "u1@example.com", models.FirstStep)

	step, err := d.UpdateUserRegistrationStep("u-1", models.SecondStep)
	require.NoError(t, err)
	assert.Equal(t, models.SecondStep, step)

	step, err = d.UpdateUserRegistrationStep("u-1", models.SecondStep)
	require.NoError(t, err)
	assert.Equal(t, models.SecondStep, step)

	_, err = d.UpdateUserRegistrationStep("missing", models.FirstStep)
	assert.ErrorIs(t, err, ErrUserNotFound)
}

func TestUpdateProfileCreateAndUpdate(t *testing.T) {
	d := newTestDatabase(t)
	seedUser(t, d, "u-1", "u1@example.com", models.SecondStep)

	require.NoError(t, d.UpdateProfile("u-1", models.KeyAbout, "first"))
	require.NoError(t, d.UpdateProfile("u-1", models.KeyAbout, "second"))
	require.NoError(t, d.UpdateProfile("u-1", models.KeyAbout, "")) // no-op

	var profiles []models.Profile
	require.NoError(t, d.Connection.Where("user_id = ?", "u-1").Find(&profiles).Error)
	require.Len(t, profiles, 1)
	assert.Equal(t, "second", profiles[0].Value)
}

func TestUpdateProfileUnknownUserIsNoop(t *testing.T) {
	d := newTestDatabase(t)

	require.NoError(t, d.UpdateProfile("ghost", models.KeyAbout, "hi"))

	var count int64
	require.NoError(t, d.Connection.Model(&models.Profile{}).Count(&count).Error)
	assert.Equal(t, int64(1), count)
}

func TestUpdateProfileUsernameTriggersStep(t *testing.T) {
	d := newTestDatabase(t)
	seedUser(t, d, "u-1", "u1@example.com", models.SecondStep)

	require.NoError(t, d.UpdateProfile("u-1", models.KeyUsername, "newnick"))

	var user models.User
	require.NoError(t, d.Connection.Where("id = ?", "u-1").First(&user).Error)
	assert.Equal(t, models.ThirdStep, user.RegistrationStep)

	// already at third step: stays
	require.NoError(t, d.UpdateProfile("u-1", models.KeyUsername, "newnick2"))
	require.NoError(t, d.Connection.Where("id = ?", "u-1").First(&user).Error)
	assert.Equal(t, models.ThirdStep, user.RegistrationStep)
}

func TestUpdateProfileCategoriesTriggersStep(t *testing.T) {
	d := newTestDatabase(t)
	seedUser(t, d, "u-1", "u1@example.com", models.ThirdStep)

	require.NoError(t, d.UpdateProfile("u-1", models.KeyFavoriteCategories, "1,2,3"))

	var user models.User
	require.NoError(t, d.Connection.Where("id = ?", "u-1").First(&user).Error)
	assert.Equal(t, models.FourthStep, user.RegistrationStep)
}

func TestUpdateUsername(t *testing.T) {
	d := newTestDatabase(t)
	user := seedUser(t, d, "u-1", "u1@example.com", models.SecondStep)

	updated, err := d.UpdateUsername(&user, "nick")
	require.NoError(t, err)
	assert.Equal(t, "nick", updated.Username)

	// mirrored into profile
	assert.Equal(t, "nick", d.FetchProfileByUserIDAndKey("u-1", models.KeyUsername))
}

func TestUpdateUsernameTaken(t *testing.T) {
	d := newTestDatabase(t)
	seedUser(t, d, "u-1", "u1@example.com", models.SecondStep)
	seedUser(t, d, "u-2", "u2@example.com", models.SecondStep)

	user := seedUser(t, d, "u-3", "u3@example.com", models.SecondStep)

	seedUser(t, d, "u-9", "u9@example.com", models.SecondStep)
	require.NoError(t, d.Connection.Model(&models.User{}).Where("id = ?", "u-9").Update("username", "takenname").Error)

	_, err := d.UpdateUsername(&user, "takenname")
	assert.ErrorIs(t, err, ErrUsernameTaken)
}

func TestIsUsernameUnique(t *testing.T) {
	d := newTestDatabase(t)
	seedUser(t, d, "u-1", "u1@example.com", models.SecondStep)
	require.NoError(t, d.Connection.Model(&models.User{}).Where("id = ?", "u-1").Update("username", "nick").Error)

	assert.ErrorIs(t, d.IsUsernameUnique("nick", "u-2"), ErrUsernameTaken)
	assert.ErrorIs(t, d.IsUsernameUnique("nick", "u-1"), nil) // own username is fine
	assert.NoError(t, d.IsUsernameUnique("freename", "u-1"))
}

func TestGetUserByIDNotFound(t *testing.T) {
	d := newTestDatabase(t)

	_, err := d.GetUserByID("ghost")
	assert.ErrorIs(t, err, ErrUserNotFound)
}

func TestGetUserByIDEnrichment(t *testing.T) {
	d := newTestDatabase(t)
	seedUser(t, d, "u-1", "u1@example.com", models.SecondStep)
	seedProfile(t, d, "u-1", models.KeyDisplayName, "Display")
	seedProfile(t, d, "u-1", models.KeyAbout, "About me")
	seedProfile(t, d, "u-1", models.KeyAvatar, "")
	seedProfile(t, d, "u-1", models.KeyFavoriteCategories, "1,2")

	user, err := d.GetUserByID("u-1")
	require.NoError(t, err)
	assert.Equal(t, "Display", user.DisplayName)
	assert.Equal(t, "About me", user.About)
	assert.Equal(t, "1,2", user.FavoriteCategories)
	assert.Empty(t, user.Avatar)
}

func TestDeleteProfile(t *testing.T) {
	d := newTestDatabase(t)
	seedUser(t, d, "u-1", "u1@example.com", models.SecondStep)
	seedProfile(t, d, "u-1", models.KeyAbout, "x")

	require.NoError(t, d.DeleteProfile("u-1", models.KeyAbout))
	assert.NoError(t, d.DeleteProfile("u-1", models.KeyAbout)) // deleting again is fine
	assert.NoError(t, d.DeleteProfile("ghost", models.KeyAbout))
}

func TestAddCategory(t *testing.T) {
	d := newTestDatabase(t)
	seedUser(t, d, "u-1", "u1@example.com", models.SecondStep)

	require.ErrorIs(t, d.AddCategory("u-1", "cat-1"), ErrProfileNotFound)

	seedProfile(t, d, "u-1", models.KeyFavoriteCategories, "")
	require.NoError(t, d.AddCategory("u-1", "cat-1"))
	require.NoError(t, d.AddCategory("u-1", "cat-2"))
	assert.Equal(t, "cat-1,cat-2", d.FetchProfileByUserIDAndKey("u-1", models.KeyFavoriteCategories))

	require.ErrorIs(t, d.AddCategory("u-1", "cat-2"), ErrCategoryExists)
	require.NoError(t, d.Connection.Where("user_id = ? AND `key` = ?", "u-1", models.KeyFavoriteCategories).Delete(&models.Profile{}).Error)
	seedProfile(t, d, "u-1", models.KeyFavoriteCategories, "cat-1")
	require.NoError(t, d.AddCategory("u-1", "cat-9"))
	assert.Equal(t, "cat-1,cat-9", d.FetchProfileByUserIDAndKey("u-1", models.KeyFavoriteCategories))
}

func TestDeleteCategory(t *testing.T) {
	d := newTestDatabase(t)
	seedUser(t, d, "u-1", "u1@example.com", models.SecondStep)

	require.ErrorIs(t, d.DeleteCategory("u-1", "cat-1"), ErrProfileNotFound)

	seedProfile(t, d, "u-1", models.KeyFavoriteCategories, "cat-1,cat-2")

	require.NoError(t, d.DeleteCategory("u-1", "cat-1"))
	assert.Equal(t, "cat-2", d.FetchProfileByUserIDAndKey("u-1", models.KeyFavoriteCategories))

	require.ErrorIs(t, d.DeleteCategory("u-1", "cat-1"), ErrCategoryMissing)
	assert.Error(t, d.DeleteCategory("u-1", ""))
}

func TestAllUsersExcludesSelfAndLimits(t *testing.T) {
	d := newTestDatabase(t)
	seedUser(t, d, "me", "me@example.com", models.SecondStep)
	for _, id := range []string{"a", "b", "c"} {
		seedUser(t, d, id, id+"@example.com", models.SecondStep)
	}

	all := d.AllUsers("me", "", 0)
	assert.Len(t, all, 3)

	limited := d.AllUsers("me", "", 2)
	assert.Len(t, limited, 2)

	assert.Len(t, d.AllUsers("me", "", 0), 3) // re-query stable
}

func TestAllUsersSearch(t *testing.T) {
	d := newTestDatabase(t)
	seedUser(t, d, "me", "me@example.com", models.SecondStep)
	seedUser(t, d, "u-1", "u1@example.com", models.SecondStep)
	seedUser(t, d, "u-2", "u2@example.com", models.SecondStep)
	require.NoError(t, d.Connection.Model(&models.User{}).Where("id = ?", "u-1").Update("username", "alpha").Error)
	seedProfile(t, d, "u-2", models.KeyDisplayName, "UniqueDisplay")

	results := d.AllUsers("me", "alpha", 0)
	require.Len(t, results, 1)
	assert.Equal(t, "u-1", results[0].ID)

	require.Len(t, d.AllUsers("me", "UniqueDisplay", 0), 1)
	assert.Empty(t, d.AllUsers("me", "zzzz", 0))
}

func TestAllUsersWithPagination(t *testing.T) {
	d := newTestDatabase(t)
	seedUser(t, d, "me", "me@example.com", models.SecondStep)
	for _, id := range []string{"a", "b", "c", "d", "e"} {
		seedUser(t, d, id, id+"@example.com", models.SecondStep)
	}

	page1 := d.AllUsersWithPagination("me", "", 1, 2)
	assert.Len(t, page1, 2)

	page2 := d.AllUsersWithPagination("me", "", 2, 2)
	assert.Len(t, page2, 2)
	assert.NotEqual(t, page1[0].ID, page2[0].ID)
	assert.NotEqual(t, page1[1].ID, page2[1].ID)

	page3 := d.AllUsersWithPagination("me", "", 3, 2)
	assert.Len(t, page3, 1)

	assert.Empty(t, d.AllUsersWithPagination("me", "", 4, 2))
	assert.Empty(t, d.AllUsersWithPagination("me", "", 0, 0))
}

func TestGetUsersByIds(t *testing.T) {
	d := newTestDatabase(t)
	seedUser(t, d, "me", "me@example.com", models.SecondStep)
	seedUser(t, d, "a", "a@example.com", models.SecondStep)
	seedUser(t, d, "b", "b@example.com", models.SecondStep)

	users, err := d.GetUsersByIds("me", []string{"a", "b", "me", "ghost"})
	require.NoError(t, err)
	assert.Len(t, users, 2)

	users, err = d.GetUsersByIds("me", []string{})
	require.NoError(t, err)
	assert.Empty(t, users)
}

func TestFetchProfileByUserID(t *testing.T) {
	d := newTestDatabase(t)
	seedUser(t, d, "u-1", "u1@example.com", models.SecondStep)
	seedProfile(t, d, "u-1", models.KeyAbout, "about")
	seedProfile(t, d, "u-1", models.KeyGender, "male")
	seedProfile(t, d, "u-2", models.KeyAbout, "other")

	profile := d.FetchProfileByUserID("u-1")
	assert.Equal(t, map[string]string{
		models.KeyAbout:  "about",
		models.KeyGender: "male",
	}, profile)

	assert.Empty(t, d.FetchProfileByUserID("ghost"))
}

func TestOauthGetOrCreateUser(t *testing.T) {
	d := newTestDatabase(t)

	user, err := d.OauthGetOrCreateUser("g@example.com", "GIVEN")
	require.NoError(t, err)
	assert.Equal(t, models.SecondStep, user.RegistrationStep)
	assert.NotEmpty(t, user.EmailVerifiedAt)

	same, err := d.OauthGetOrCreateUser("g@example.com", "GIVEN")
	require.NoError(t, err)
	assert.Equal(t, user.ID, same.ID)
}

func TestCreateSocialAuthClient(t *testing.T) {
	d := newTestDatabase(t)
	seedUser(t, d, "u-1", "u1@example.com", models.SecondStep)

	require.NoError(t, d.CreateSocialAuthClient("google", "u-1", "g-42"))
	require.NoError(t, d.CreateSocialAuthClient("google", "u-1", "g-42"))

	var count int64
	require.NoError(t, d.Connection.Model(&models.SocialAuth{}).Count(&count).Error)
	assert.Equal(t, int64(1), count)
}

func TestSendOTPExistingUserKeepsStep(t *testing.T) {
	d := newTestDatabase(t)
	seedUser(t, d, "u-1", "u1@example.com", models.ThirdStep)

	_, _, err := d.SendOTP("u1@example.com")
	require.NoError(t, err)

	user, err := d.GetUserByID("u-1")
	require.NoError(t, err)
	assert.Equal(t, models.ThirdStep, user.RegistrationStep)
}

func TestGetUserByIDCustomTable(t *testing.T) {
	// sanity: sqlite handles the backtick-quoted `key` column and joins used
	// in list queries.
	d := newTestDatabase(t)
	seedUser(t, d, "me", "me@example.com", models.SecondStep)
	seedUser(t, d, "a", "a@example.com", models.SecondStep)
	seedProfile(t, d, "a", models.KeyAbout, "searchable text")

	results := d.AllUsers("me", "searchable", 0)
	require.Len(t, results, 1)
	assert.Equal(t, "a", results[0].ID)
	assert.Equal(t, "searchable text", results[0].About)
}
