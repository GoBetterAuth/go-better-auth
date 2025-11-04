package auth

import (
	"context"
	"testing"
	"time"

	"github.com/GoBetterAuth/go-better-auth/domain"
	"github.com/GoBetterAuth/go-better-auth/domain/account"
	gobetterauthtests "github.com/GoBetterAuth/go-better-auth/tests"
)

func TestSignUp_Valid(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := NewService(
		gobetterauthtests.CreateTestConfig(),
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	req := &SignUpRequest{
		Email:    "user@example.com",
		Password: "ValidPassword123!",
		Name:     "Test User",
	}

	resp, err := service.SignUp(context.Background(), req)
	if err != nil {
		t.Fatalf("SignUp failed: %v", err)
	}

	if resp == nil || resp.User == nil {
		t.Fatal("SignUp returned nil user")
	}

	if resp.User.Email != req.Email {
		t.Errorf("Expected email %s, got %s", req.Email, resp.User.Email)
	}

	if resp.User.Name != req.Name {
		t.Errorf("Expected name %s, got %s", req.Name, resp.User.Name)
	}

	if resp.User.EmailVerified != true {
		t.Errorf("Expected EmailVerified to be true (email verification not configured), got %v", resp.User.EmailVerified)
	}

	if resp.User.ID == "" {
		t.Error("Expected user ID to be set")
	}
}

func TestSignUp_DuplicateEmail(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := NewService(
		gobetterauthtests.CreateTestConfig(),
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	req1 := &SignUpRequest{
		Email:    "user@example.com",
		Password: "ValidPassword123!",
		Name:     "User 1",
	}

	// First signup should succeed
	_, err := service.SignUp(context.Background(), req1)
	if err != nil {
		t.Fatalf("First SignUp failed: %v", err)
	}

	// Second signup with same email should fail
	req2 := &SignUpRequest{
		Email:    "user@example.com",
		Password: "DifferentPassword456!",
		Name:     "User 2",
	}

	_, err = service.SignUp(context.Background(), req2)
	if err == nil {
		t.Fatal("Expected duplicate email error, got nil")
	}
}

func TestSignUp_InvalidEmail(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := NewService(
		gobetterauthtests.CreateTestConfig(),
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	tests := []struct {
		name  string
		email string
	}{
		{"empty", ""},
		{"spaces", "   "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &SignUpRequest{
				Email:    tt.email,
				Password: "ValidPassword123!",
				Name:     "Test User",
			}

			_, err := service.SignUp(context.Background(), req)
			if err == nil {
				t.Fatal("Expected validation error for empty email")
			}
		})
	}
}

func TestSignUp_InvalidPassword(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := NewService(
		gobetterauthtests.CreateTestConfig(),
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	tests := []struct {
		name     string
		password string
	}{
		{"empty", ""},
		{"too_short", "short"},
		{"spaces", "   "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &SignUpRequest{
				Email:    "user@example.com",
				Password: tt.password,
				Name:     "Test User",
			}

			_, err := service.SignUp(context.Background(), req)
			if err == nil {
				t.Fatalf("Expected validation error for password %q", tt.password)
			}
		})
	}
}

func TestSignUp_InvalidName(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := NewService(
		gobetterauthtests.CreateTestConfig(),
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	req := &SignUpRequest{
		Email:    "user@example.com",
		Password: "ValidPassword123!",
		Name:     "",
	}

	_, err := service.SignUp(context.Background(), req)
	if err == nil {
		t.Fatal("Expected validation error for empty name")
	}
}

func TestSignUp_PasswordHashing(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := NewService(
		gobetterauthtests.CreateTestConfig(),
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	req := &SignUpRequest{
		Email:    "user@example.com",
		Password: "MySecurePassword123!",
		Name:     "Test User",
	}

	resp, err := service.SignUp(context.Background(), req)
	if err != nil {
		t.Fatalf("SignUp failed: %v", err)
	}

	// Find the account and verify password is hashed
	acc, err := repos.AccountRepo.FindByUserIDAndProvider(resp.User.ID, account.ProviderCredential)
	if err != nil {
		t.Fatalf("Failed to find account: %v", err)
	}

	if acc.Password == nil {
		t.Fatal("Account password is nil")
	}

	// Password should be hashed, not the same as input
	if *acc.Password == req.Password {
		t.Error("Password was not hashed")
	}

	// Password should be a reasonable length for argon2
	if len(*acc.Password) < 50 {
		t.Errorf("Hashed password seems too short: %d bytes", len(*acc.Password))
	}
}

func TestSignUp_CreatedAccountWithProvider(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := NewService(
		gobetterauthtests.CreateTestConfig(),
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	req := &SignUpRequest{
		Email:    "user@example.com",
		Password: "ValidPassword123!",
		Name:     "Test User",
	}

	resp, err := service.SignUp(context.Background(), req)
	if err != nil {
		t.Fatalf("SignUp failed: %v", err)
	}

	// Find the account
	acc, err := repos.AccountRepo.FindByUserIDAndProvider(resp.User.ID, account.ProviderCredential)
	if err != nil {
		t.Fatalf("Failed to find account: %v", err)
	}

	if acc.UserID != resp.User.ID {
		t.Errorf("Expected account UserID %s, got %s", resp.User.ID, acc.UserID)
	}

	if acc.ProviderID != account.ProviderCredential {
		t.Errorf("Expected provider %s, got %s", account.ProviderCredential, acc.ProviderID)
	}

	if acc.ID == "" {
		t.Error("Expected account ID to be set")
	}
}

func TestSignUp_TimestampsSet(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := NewService(
		gobetterauthtests.CreateTestConfig(),
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	beforeTime := time.Now()

	req := &SignUpRequest{
		Email:    "user@example.com",
		Password: "ValidPassword123!",
		Name:     "Test User",
	}

	resp, err := service.SignUp(context.Background(), req)
	if err != nil {
		t.Fatalf("SignUp failed: %v", err)
	}

	afterTime := time.Now()

	if resp.User.CreatedAt.Before(beforeTime) || resp.User.CreatedAt.After(afterTime) {
		t.Errorf("CreatedAt timestamp not set correctly")
	}

	if resp.User.UpdatedAt.Before(beforeTime) || resp.User.UpdatedAt.After(afterTime) {
		t.Errorf("UpdatedAt timestamp not set correctly")
	}
}

func TestSignUpRequest_Validate(t *testing.T) {
	tests := []struct {
		name    string
		req     *SignUpRequest
		wantErr bool
	}{
		{
			name: "valid",
			req: &SignUpRequest{
				Email:    "user@example.com",
				Password: "ValidPassword123!",
				Name:     "Test User",
			},
			wantErr: false,
		},
		{
			name: "missing_email",
			req: &SignUpRequest{
				Password: "ValidPassword123!",
				Name:     "Test User",
			},
			wantErr: true,
		},
		{
			name: "missing_password",
			req: &SignUpRequest{
				Email: "user@example.com",
				Name:  "Test User",
			},
			wantErr: true,
		},
		{
			name: "password_too_short",
			req: &SignUpRequest{
				Email:    "user@example.com",
				Password: "short",
				Name:     "Test User",
			},
			wantErr: true,
		},
		{
			name: "missing_name",
			req: &SignUpRequest{
				Email:    "user@example.com",
				Password: "ValidPassword123!",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate(nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSignUp_Disabled(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	config := gobetterauthtests.CreateTestConfig()
	config.EmailAndPassword = &domain.EmailPasswordConfig{
		Enabled:                  true,
		DisableSignUp:            true,
		RequireEmailVerification: false,
		MinPasswordLength:        8,
		MaxPasswordLength:        128,
	}

	service := NewService(
		config,
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	req := &SignUpRequest{
		Email:    "user@example.com",
		Password: "ValidPassword123!",
		Name:     "Test User",
	}

	resp, err := service.SignUp(context.Background(), req)
	if err == nil {
		t.Fatal("Expected error when signup is disabled, got nil")
	}

	if resp != nil {
		t.Fatal("Expected nil response when signup is disabled")
	}

	if err.Error() != "email/password is disabled" {
		t.Errorf("Expected 'email/password is disabled' error, got: %v", err)
	}
}
