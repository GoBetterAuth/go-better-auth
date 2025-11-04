package auth

import (
	"context"
	"testing"

	"github.com/GoBetterAuth/go-better-auth/domain"
	"github.com/GoBetterAuth/go-better-auth/internal/crypto"
	gobetterauthtests "github.com/GoBetterAuth/go-better-auth/tests"
)

func TestSignIn_Valid(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	// Create a user
	password := "ValidPassword123!"
	hashedPassword, err := crypto.HashPassword(password)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	// Manually create user and account
	testUser := gobetterauthtests.CreateTestUser()
	if err := repos.UserRepo.Create(testUser); err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	testAccount := gobetterauthtests.CreateTestAccount(testUser.ID, &hashedPassword)
	if err := repos.AccountRepo.Create(testAccount); err != nil {
		t.Fatalf("Failed to create test account: %v", err)
	}

	service := NewService(
		gobetterauthtests.CreateTestConfig(), repos.UserRepo, repos.SessionRepo, repos.AccountRepo, repos.VerificationRepo)

	req := &SignInRequest{
		Email:     testUser.Email,
		Password:  password,
		IPAddress: "192.168.1.1",
		UserAgent: "Mozilla/5.0",
	}

	resp, err := service.SignIn(context.Background(), req)
	if err != nil {
		t.Fatalf("SignIn failed: %v", err)
	}

	if resp == nil || resp.Session == nil {
		t.Fatal("SignIn returned nil session")
	}

	if resp.Session.UserID != testUser.ID {
		t.Errorf("Expected UserID %s, got %s", testUser.ID, resp.Session.UserID)
	}

	if resp.Session.Token == "" {
		t.Error("Expected session token to be set")
	}

	if resp.Session.ExpiresAt.IsZero() {
		t.Error("Expected session ExpiresAt to be set")
	}
}

func TestSignIn_InvalidPassword(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	// Create a user with a specific password
	password := "ValidPassword123!"
	hashedPassword, _ := crypto.HashPassword(password)

	testUser := gobetterauthtests.CreateTestUser()
	repos.UserRepo.Create(testUser)

	testAccount := gobetterauthtests.CreateTestAccount(testUser.ID, &hashedPassword)
	repos.AccountRepo.Create(testAccount)

	service := NewService(
		gobetterauthtests.CreateTestConfig(), repos.UserRepo, repos.SessionRepo, repos.AccountRepo, repos.VerificationRepo)

	req := &SignInRequest{
		Email:     testUser.Email,
		Password:  "WrongPassword123!",
		IPAddress: "192.168.1.1",
		UserAgent: "Mozilla/5.0",
	}

	_, err := service.SignIn(context.Background(), req)
	if err == nil {
		t.Fatal("Expected error for invalid password, got nil")
	}
}

func TestSignIn_UserNotFound(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := NewService(
		gobetterauthtests.CreateTestConfig(),
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	req := &SignInRequest{
		Email:     "nonexistent@example.com",
		Password:  "SomePassword123!",
		IPAddress: "192.168.1.1",
		UserAgent: "Mozilla/5.0",
	}

	_, err := service.SignIn(context.Background(), req)
	if err == nil {
		t.Fatal("Expected error for non-existent user, got nil")
	}
}

func TestSignIn_AccountNotFound(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	// Create a user without an account
	testUser := gobetterauthtests.CreateTestUser()
	repos.UserRepo.Create(testUser)

	service := NewService(
		gobetterauthtests.CreateTestConfig(), repos.UserRepo, repos.SessionRepo, repos.AccountRepo, repos.VerificationRepo)

	req := &SignInRequest{
		Email:     testUser.Email,
		Password:  "SomePassword123!",
		IPAddress: "192.168.1.1",
		UserAgent: "Mozilla/5.0",
	}

	_, err := service.SignIn(context.Background(), req)
	if err == nil {
		t.Fatal("Expected error for user without account, got nil")
	}
}

func TestSignInRequest_Validate(t *testing.T) {
	tests := []struct {
		name    string
		req     *SignInRequest
		wantErr bool
	}{
		{
			name: "valid",
			req: &SignInRequest{
				Email:    "user@example.com",
				Password: "ValidPassword123!",
			},
			wantErr: false,
		},
		{
			name: "missing_email",
			req: &SignInRequest{
				Password: "ValidPassword123!",
			},
			wantErr: true,
		},
		{
			name: "missing_password",
			req: &SignInRequest{
				Email: "user@example.com",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSignOut_Valid(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	// Create a test user first to satisfy foreign key constraint
	testUser := gobetterauthtests.CreateTestUser()
	err := repos.UserRepo.Create(testUser)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Create a test session with the existing user
	testSession := gobetterauthtests.CreateTestSession()
	testSession.UserID = testUser.ID
	repos.SessionRepo.Create(testSession)

	service := NewService(
		gobetterauthtests.CreateTestConfig(),
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	req := &SignOutRequest{
		SessionToken: testSession.Token,
	}

	signOutErr := service.SignOut(req)
	if signOutErr != nil {
		t.Fatalf("SignOut failed: %v", signOutErr)
	}

	// Verify session is deleted
	_, err = repos.SessionRepo.FindByToken(testSession.Token)
	if err == nil {
		t.Fatal("Expected session to be deleted, but it was found")
	}
}

func TestSignOut_InvalidToken(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := NewService(
		gobetterauthtests.CreateTestConfig(),
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	req := &SignOutRequest{
		SessionToken: "invalid-token",
	}

	err := service.SignOut(req)
	if err == nil {
		t.Fatal("Expected error for invalid session token, got nil")
	}
}

func TestSignIn_WithDisabledSignUp(t *testing.T) {
	// Verify that existing users can still sign in even when signup is disabled
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	// Create a user
	password := "ValidPassword123!"
	hashedPassword, err := crypto.HashPassword(password)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	// Manually create user and account
	testUser := gobetterauthtests.CreateTestUser()
	if err := repos.UserRepo.Create(testUser); err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	testAccount := gobetterauthtests.CreateTestAccount(testUser.ID, &hashedPassword)
	if err := repos.AccountRepo.Create(testAccount); err != nil {
		t.Fatalf("Failed to create test account: %v", err)
	}

	// Create config with disabled signup
	config := gobetterauthtests.CreateTestConfig()
	config.EmailAndPassword = &domain.EmailPasswordConfig{
		Enabled:                  true,
		DisableSignUp:            true,
		RequireEmailVerification: false,
		MinPasswordLength:        8,
		MaxPasswordLength:        128,
	}

	service := NewService(config, repos.UserRepo, repos.SessionRepo, repos.AccountRepo, repos.VerificationRepo)

	req := &SignInRequest{
		Email:     testUser.Email,
		Password:  password,
		IPAddress: "192.168.1.1",
		UserAgent: "Mozilla/5.0",
	}

	resp, err := service.SignIn(context.Background(), req)
	if err != nil {
		t.Fatalf("SignIn failed when signup is disabled: %v", err)
	}

	if resp == nil || resp.Session == nil {
		t.Fatal("SignIn returned nil response when signup is disabled")
	}

	if resp.User.Email != testUser.Email {
		t.Errorf("Expected user email %s, got %s", testUser.Email, resp.User.Email)
	}
}
