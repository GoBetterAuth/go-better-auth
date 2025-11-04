package tests

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetupTestRepositories(t *testing.T) {
	repos, cleanup := SetupTestRepositories(t)
	defer cleanup()

	// Test that repositories are not nil
	assert.NotNil(t, repos.UserRepo)
	assert.NotNil(t, repos.SessionRepo)
	assert.NotNil(t, repos.AccountRepo)
	assert.NotNil(t, repos.VerificationRepo)

	// Test creating a user
	user := CreateTestUser()
	err := repos.UserRepo.Create(user)
	require.NoError(t, err)

	// Test retrieving the user
	retrievedUser, err := repos.UserRepo.FindByID(user.ID)
	require.NoError(t, err)
	assert.Equal(t, user.Email, retrievedUser.Email)
	assert.Equal(t, user.Name, retrievedUser.Name)
}

func TestCreateTestUser(t *testing.T) {
	user := CreateTestUser()

	assert.NotEmpty(t, user.ID)
	assert.Equal(t, "test@example.com", user.Email)
	assert.Equal(t, "Test User", user.Name)
	assert.False(t, user.EmailVerified)
}

func TestCreateTestSession(t *testing.T) {
	session := CreateTestSession()

	assert.NotEmpty(t, session.ID)
	assert.NotEmpty(t, session.UserID)
	assert.NotEmpty(t, session.Token)
	assert.True(t, session.ExpiresAt.After(session.CreatedAt))
}

func TestCreateTestAccount(t *testing.T) {
	userID := "test-user-id"
	password := "test-password"

	account := CreateTestAccount(userID, &password)

	assert.NotEmpty(t, account.ID)
	assert.Equal(t, userID, account.UserID)
	assert.NotNil(t, account.Password)
	assert.Equal(t, password, *account.Password)
}
