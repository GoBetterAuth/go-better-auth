package auth

import (
	"context"
	"fmt"
	"testing"

	"github.com/GoBetterAuth/go-better-auth/domain"
	"github.com/GoBetterAuth/go-better-auth/domain/user"
	gobetterauthtests "github.com/GoBetterAuth/go-better-auth/tests"
)

func TestDeleteUser_Success(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	config := gobetterauthtests.CreateTestConfig()
	service := NewService(config, repos.UserRepo, repos.SessionRepo, repos.AccountRepo, repos.VerificationRepo)

	// Create a test user
	user := gobetterauthtests.CreateTestUser()
	if err := repos.UserRepo.Create(user); err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	// Create a test session for the user
	session := gobetterauthtests.CreateTestSession()
	session.UserID = user.ID
	if err := repos.SessionRepo.Create(session); err != nil {
		t.Fatalf("failed to create test session: %v", err)
	}

	// Create a test account for the user
	passwordHash := "hashed_password"
	acc := gobetterauthtests.CreateTestAccount(user.ID, &passwordHash)
	if err := repos.AccountRepo.Create(acc); err != nil {
		t.Fatalf("failed to create test account: %v", err)
	}

	// Delete the user
	resp, err := service.DeleteUser(&DeleteUserRequest{
		UserID: user.ID,
	})
	if err != nil {
		t.Fatalf("DeleteUser failed: %v", err)
	}

	if resp == nil || !resp.Success {
		t.Fatal("DeleteUser response should indicate success")
	}

	// Verify user is deleted
	_, err = repos.UserRepo.FindByID(user.ID)
	if err == nil {
		t.Fatal("User should be deleted")
	}

	// Verify sessions are deleted
	sessions, err := repos.SessionRepo.FindByUserID(user.ID)
	if err != nil {
		t.Fatalf("FindByUserID failed: %v", err)
	}
	if len(sessions) > 0 {
		t.Fatal("All user sessions should be deleted")
	}

	// Verify accounts are deleted
	accounts, err := repos.AccountRepo.FindByUserID(user.ID)
	if err != nil {
		t.Fatalf("FindByUserID failed: %v", err)
	}
	if len(accounts) > 0 {
		t.Fatal("All user accounts should be deleted")
	}
}

func TestDeleteUser_WithBeforeHook_Success(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	config := gobetterauthtests.CreateTestConfig()

	// Track hook calls
	beforeHookCalled := false
	var capturedUser *user.User

	// Set up the before delete hook
	config.User = &domain.UserConfig{
		DeleteUser: &domain.DeleteUserConfig{
			BeforeDelete: func(ctx context.Context, user *user.User) error {
				beforeHookCalled = true
				capturedUser = user
				return nil
			},
		},
	}

	service := NewService(
		config,
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	// Create a test user
	user := gobetterauthtests.CreateTestUser()
	if err := repos.UserRepo.Create(user); err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	// Delete the user
	resp, err := service.DeleteUser(&DeleteUserRequest{
		UserID: user.ID,
	})
	if err != nil {
		t.Fatalf("DeleteUser failed: %v", err)
	}

	if !resp.Success {
		t.Fatal("DeleteUser should succeed")
	}

	// Verify hook was called
	if !beforeHookCalled {
		t.Fatal("BeforeDelete hook should have been called")
	}

	// Verify correct user was passed to hook
	if capturedUser == nil {
		t.Fatal("User should have been passed to hook")
	}
	if capturedUser.ID != user.ID {
		t.Fatalf("Expected user ID %s, got %s", user.ID, capturedUser.ID)
	}
	if capturedUser.Email != user.Email {
		t.Fatalf("Expected user email %s, got %s", user.Email, capturedUser.Email)
	}
}

func TestDeleteUser_WithAfterHook_Success(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	config := gobetterauthtests.CreateTestConfig()

	// Track hook calls
	afterHookCalled := false
	var capturedUser *user.User

	// Set up the after delete hook
	config.User = &domain.UserConfig{
		DeleteUser: &domain.DeleteUserConfig{
			AfterDelete: func(ctx context.Context, user *user.User) error {
				afterHookCalled = true
				capturedUser = user
				return nil
			},
		},
	}

	service := NewService(
		config,
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	// Create a test user
	user := gobetterauthtests.CreateTestUser()
	if err := repos.UserRepo.Create(user); err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	// Delete the user
	resp, err := service.DeleteUser(&DeleteUserRequest{
		UserID: user.ID,
	})
	if err != nil {
		t.Fatalf("DeleteUser failed: %v", err)
	}

	if !resp.Success {
		t.Fatal("DeleteUser should succeed")
	}

	// Verify hook was called
	if !afterHookCalled {
		t.Fatal("AfterDelete hook should have been called")
	}

	// Verify correct user was passed to hook
	if capturedUser == nil {
		t.Fatal("User should have been passed to hook")
	}
	if capturedUser.ID != user.ID {
		t.Fatalf("Expected user ID %s, got %s", user.ID, capturedUser.ID)
	}
}

func TestDeleteUser_WithBothHooks_Success(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	config := gobetterauthtests.CreateTestConfig()

	// Track hook calls
	beforeHookCalled := false
	afterHookCalled := false
	var callOrder []string

	// Set up both hooks
	config.User = &domain.UserConfig{
		DeleteUser: &domain.DeleteUserConfig{
			BeforeDelete: func(ctx context.Context, user *user.User) error {
				beforeHookCalled = true
				callOrder = append(callOrder, "before")
				return nil
			},
			AfterDelete: func(ctx context.Context, user *user.User) error {
				afterHookCalled = true
				callOrder = append(callOrder, "after")
				return nil
			},
		},
	}

	service := NewService(
		config,
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	// Create a test user
	user := gobetterauthtests.CreateTestUser()
	if err := repos.UserRepo.Create(user); err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	// Delete the user
	resp, err := service.DeleteUser(&DeleteUserRequest{
		UserID: user.ID,
	})
	if err != nil {
		t.Fatalf("DeleteUser failed: %v", err)
	}

	if !resp.Success {
		t.Fatal("DeleteUser should succeed")
	}

	// Verify both hooks were called
	if !beforeHookCalled {
		t.Fatal("BeforeDelete hook should have been called")
	}
	if !afterHookCalled {
		t.Fatal("AfterDelete hook should have been called")
	}

	// Verify correct order
	if len(callOrder) != 2 {
		t.Fatalf("Expected 2 hook calls, got %d", len(callOrder))
	}
	if callOrder[0] != "before" {
		t.Fatal("BeforeDelete should be called first")
	}
	if callOrder[1] != "after" {
		t.Fatal("AfterDelete should be called second")
	}
}

func TestDeleteUser_BeforeHookError_StopsExecution(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	config := gobetterauthtests.CreateTestConfig()

	expectedError := fmt.Errorf("before hook error")
	afterHookCalled := false

	// Set up hooks with before hook that returns an error
	config.User = &domain.UserConfig{
		DeleteUser: &domain.DeleteUserConfig{
			BeforeDelete: func(ctx context.Context, user *user.User) error {
				return expectedError
			},
			AfterDelete: func(ctx context.Context, user *user.User) error {
				afterHookCalled = true
				return nil
			},
		},
	}

	service := NewService(
		config,
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	// Create a test user
	user := gobetterauthtests.CreateTestUser()
	if err := repos.UserRepo.Create(user); err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	// Attempt to delete the user
	resp, err := service.DeleteUser(&DeleteUserRequest{
		UserID: user.ID,
	})
	if err == nil {
		t.Fatal("DeleteUser should fail when before hook returns error")
	}

	if resp != nil {
		t.Fatal("Response should be nil when deletion fails")
	}

	// Verify user still exists
	existingUser, err := repos.UserRepo.FindByID(user.ID)
	if err != nil {
		t.Fatal("User should still exist after failed deletion")
	}
	if existingUser.ID != user.ID {
		t.Fatal("User should not be deleted")
	}

	// Verify after hook was not called
	if afterHookCalled {
		t.Fatal("AfterDelete hook should not be called when before hook fails")
	}
}

func TestDeleteUser_AfterHookError_ReturnsError(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	config := gobetterauthtests.CreateTestConfig()

	expectedError := fmt.Errorf("after hook error")
	beforeHookCalled := false

	// Set up hooks with after hook that returns an error
	config.User = &domain.UserConfig{
		DeleteUser: &domain.DeleteUserConfig{
			BeforeDelete: func(ctx context.Context, user *user.User) error {
				beforeHookCalled = true
				return nil
			},
			AfterDelete: func(ctx context.Context, user *user.User) error {
				return expectedError
			},
		},
	}

	service := NewService(
		config,
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	// Create a test user
	user := gobetterauthtests.CreateTestUser()
	if err := repos.UserRepo.Create(user); err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	// Attempt to delete the user
	resp, err := service.DeleteUser(&DeleteUserRequest{
		UserID: user.ID,
	})
	if err == nil {
		t.Fatal("DeleteUser should fail when after hook returns error")
	}

	if resp != nil {
		t.Fatal("Response should be nil when after hook fails")
	}

	// Verify before hook was called
	if !beforeHookCalled {
		t.Fatal("BeforeDelete hook should have been called")
	}

	// Note: User is still deleted even though after hook fails
	// This is expected behavior - the after hook runs after deletion
	_, err = repos.UserRepo.FindByID(user.ID)
	if err == nil {
		t.Fatal("User should be deleted even though after hook failed")
	}
}

func TestDeleteUser_NoHooksConfigured_Success(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	config := gobetterauthtests.CreateTestConfig()
	// Don't configure any hooks

	service := NewService(
		config,
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	// Create a test user
	user := gobetterauthtests.CreateTestUser()
	if err := repos.UserRepo.Create(user); err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	// Delete the user
	resp, err := service.DeleteUser(&DeleteUserRequest{
		UserID: user.ID,
	})
	if err != nil {
		t.Fatalf("DeleteUser should succeed without hooks: %v", err)
	}

	if !resp.Success {
		t.Fatal("DeleteUser should succeed")
	}

	// Verify user is deleted
	_, err = repos.UserRepo.FindByID(user.ID)
	if err == nil {
		t.Fatal("User should be deleted")
	}
}
