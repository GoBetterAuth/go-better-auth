package auth

import (
	"context"
	"testing"

	gobetterauthtests "github.com/GoBetterAuth/go-better-auth/tests"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ===== UpdateUser Tests =====

func TestUpdateUser_Valid(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := NewService(
		gobetterauthtests.CreateTestConfig(),
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	// First create a user
	signupResp, err := service.SignUp(context.Background(), &SignUpRequest{
		Email:    "user@example.com",
		Password: "ValidPassword123!",
		Name:     "John Doe",
	})
	require.NoError(t, err)
	require.NotNil(t, signupResp)

	userID := signupResp.User.ID

	// Update user name
	newName := "Jane Doe"
	updateReq := &UpdateUserRequest{
		UserID: userID,
		Name:   &newName,
	}

	resp, err := service.UpdateUser(updateReq)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.User)

	assert.Equal(t, newName, resp.User.Name)
	assert.Equal(t, "user@example.com", resp.User.Email)
	assert.NotNil(t, resp.User.UpdatedAt)
}

func TestUpdateUser_UpdateImage(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := NewService(
		gobetterauthtests.CreateTestConfig(),
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	// Create a user
	signupResp, err := service.SignUp(context.Background(), &SignUpRequest{
		Email:    "user@example.com",
		Password: "ValidPassword123!",
		Name:     "John Doe",
	})
	require.NoError(t, err)

	userID := signupResp.User.ID

	// Update user image
	newImage := "https://example.com/image.jpg"
	updateReq := &UpdateUserRequest{
		UserID: userID,
		Image:  &newImage,
	}

	resp, err := service.UpdateUser(updateReq)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.User)

	assert.NotNil(t, resp.User.Image)
	assert.Equal(t, newImage, *resp.User.Image)
	assert.Equal(t, "John Doe", resp.User.Name)
}

func TestUpdateUser_UpdateBothNameAndImage(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := NewService(
		gobetterauthtests.CreateTestConfig(),
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	// Create a user
	signupResp, err := service.SignUp(context.Background(), &SignUpRequest{
		Email:    "user@example.com",
		Password: "ValidPassword123!",
		Name:     "John Doe",
	})
	require.NoError(t, err)

	userID := signupResp.User.ID

	// Update both name and image
	newName := "Jane Smith"
	newImage := "https://example.com/profile.jpg"
	updateReq := &UpdateUserRequest{
		UserID: userID,
		Name:   &newName,
		Image:  &newImage,
	}

	resp, err := service.UpdateUser(updateReq)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.User)

	assert.Equal(t, newName, resp.User.Name)
	assert.NotNil(t, resp.User.Image)
	assert.Equal(t, newImage, *resp.User.Image)
}

func TestUpdateUser_NilRequest(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := NewService(
		gobetterauthtests.CreateTestConfig(),
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	resp, err := service.UpdateUser(nil)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, "update user request cannot be nil", err.Error())
}

func TestUpdateUser_EmptyUserID(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := NewService(
		gobetterauthtests.CreateTestConfig(),
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	newName := "Jane Doe"
	updateReq := &UpdateUserRequest{
		UserID: "",
		Name:   &newName,
	}

	resp, err := service.UpdateUser(updateReq)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, "user ID cannot be empty", err.Error())
}

func TestUpdateUser_UserNotFound(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := NewService(
		gobetterauthtests.CreateTestConfig(),
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	newName := "Jane Doe"
	updateReq := &UpdateUserRequest{
		UserID: "non-existent-user-id",
		Name:   &newName,
	}

	resp, err := service.UpdateUser(updateReq)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "user not found")
}

func TestUpdateUser_InvalidName(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := NewService(
		gobetterauthtests.CreateTestConfig(),
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	// Create a user
	signupResp, err := service.SignUp(context.Background(), &SignUpRequest{
		Email:    "user@example.com",
		Password: "ValidPassword123!",
		Name:     "John Doe",
	})
	require.NoError(t, err)

	userID := signupResp.User.ID

	// Try to update with empty name
	emptyName := ""
	updateReq := &UpdateUserRequest{
		UserID: userID,
		Name:   &emptyName,
	}

	resp, err := service.UpdateUser(updateReq)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "invalid request")
}

func TestUpdateUser_NoChanges(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := NewService(
		gobetterauthtests.CreateTestConfig(),
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	// Create a user
	signupResp, err := service.SignUp(context.Background(), &SignUpRequest{
		Email:    "user@example.com",
		Password: "ValidPassword123!",
		Name:     "John Doe",
	})
	require.NoError(t, err)

	userID := signupResp.User.ID
	originalUser := signupResp.User

	// Update with nil values (no changes)
	updateReq := &UpdateUserRequest{
		UserID: userID,
		Name:   nil,
		Image:  nil,
	}

	resp, err := service.UpdateUser(updateReq)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.User)

	assert.Equal(t, originalUser.Name, resp.User.Name)
	assert.Equal(t, originalUser.Image, resp.User.Image)
}

// ===== DeleteUser Tests =====

func TestDeleteUser_Valid(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := NewService(
		gobetterauthtests.CreateTestConfig(),
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	// Create a user
	signupResp, err := service.SignUp(context.Background(), &SignUpRequest{
		Email:    "user@example.com",
		Password: "ValidPassword123!",
		Name:     "John Doe",
	})
	require.NoError(t, err)

	userID := signupResp.User.ID

	// Delete the user
	deleteReq := &DeleteUserRequest{
		UserID: userID,
	}

	resp, err := service.DeleteUser(deleteReq)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Success)

	// Verify user is deleted
	_, err = service.userRepo.FindByID(userID)
	assert.Error(t, err)
}

func TestDeleteUser_WithSessions(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := NewService(
		gobetterauthtests.CreateTestConfig(),
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	// Create a user
	signupResp, err := service.SignUp(context.Background(), &SignUpRequest{
		Email:    "user@example.com",
		Password: "ValidPassword123!",
		Name:     "John Doe",
	})
	require.NoError(t, err)

	userID := signupResp.User.ID

	// Create a session
	signinResp, err := service.SignIn(context.Background(), &SignInRequest{
		Email:    "user@example.com",
		Password: "ValidPassword123!",
	})
	require.NoError(t, err)
	require.NotNil(t, signinResp.Session)

	// Verify session exists
	sessions, err := service.sessionRepo.FindByUserID(userID)
	require.NoError(t, err)
	assert.Greater(t, len(sessions), 0)

	// Delete the user
	deleteReq := &DeleteUserRequest{
		UserID: userID,
	}

	resp, err := service.DeleteUser(deleteReq)
	require.NoError(t, err)
	assert.True(t, resp.Success)

	// Verify user and sessions are deleted
	_, err = service.userRepo.FindByID(userID)
	assert.Error(t, err)

	sessions, err = service.sessionRepo.FindByUserID(userID)
	assert.NoError(t, err)
	assert.Empty(t, sessions)
}

func TestDeleteUser_WithOAuthAccounts(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := NewService(
		gobetterauthtests.CreateTestConfig(),
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	// Create a user
	signupResp, err := service.SignUp(context.Background(), &SignUpRequest{
		Email:    "user@example.com",
		Password: "ValidPassword123!",
		Name:     "John Doe",
	})
	require.NoError(t, err)

	userID := signupResp.User.ID

	// Delete the user
	deleteReq := &DeleteUserRequest{
		UserID: userID,
	}

	resp, err := service.DeleteUser(deleteReq)
	require.NoError(t, err)
	assert.True(t, resp.Success)

	// Verify user is deleted
	_, err = service.userRepo.FindByID(userID)
	assert.Error(t, err)
}

func TestDeleteUser_NilRequest(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := NewService(
		gobetterauthtests.CreateTestConfig(),
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	resp, err := service.DeleteUser(nil)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, "delete user request cannot be nil", err.Error())
}

func TestDeleteUser_EmptyUserID(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := NewService(
		gobetterauthtests.CreateTestConfig(),
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	deleteReq := &DeleteUserRequest{
		UserID: "",
	}

	resp, err := service.DeleteUser(deleteReq)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, "user ID cannot be empty", err.Error())
}

func TestDeleteUser_UserNotFound(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := NewService(
		gobetterauthtests.CreateTestConfig(),
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	deleteReq := &DeleteUserRequest{
		UserID: "non-existent-user-id",
	}

	resp, err := service.DeleteUser(deleteReq)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "user not found")
}

func TestDeleteUser_MultipleSessionsDeleted(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := NewService(
		gobetterauthtests.CreateTestConfig(),
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	// Create a user
	signupResp, err := service.SignUp(context.Background(), &SignUpRequest{
		Email:    "user@example.com",
		Password: "ValidPassword123!",
		Name:     "John Doe",
	})
	require.NoError(t, err)

	userID := signupResp.User.ID

	// Create multiple sessions (by signing in multiple times)
	_, err = service.SignIn(context.Background(), &SignInRequest{
		Email:    "user@example.com",
		Password: "ValidPassword123!",
	})
	require.NoError(t, err)

	_, err = service.SignIn(context.Background(), &SignInRequest{
		Email:    "user@example.com",
		Password: "ValidPassword123!",
	})
	require.NoError(t, err)

	// Verify multiple sessions exist
	sessions, err := service.sessionRepo.FindByUserID(userID)
	require.NoError(t, err)
	sessionCount := len(sessions)
	assert.Greater(t, sessionCount, 0)

	// Delete the user
	deleteReq := &DeleteUserRequest{
		UserID: userID,
	}

	resp, err := service.DeleteUser(deleteReq)
	require.NoError(t, err)
	assert.True(t, resp.Success)

	// Verify all sessions are deleted
	sessions, err = service.sessionRepo.FindByUserID(userID)
	require.NoError(t, err)
	assert.Empty(t, sessions)
}
