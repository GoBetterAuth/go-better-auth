package auth

import (
	"context"
	"testing"
	"time"

	"github.com/GoBetterAuth/go-better-auth/domain"
	"github.com/GoBetterAuth/go-better-auth/domain/verification"
	"github.com/GoBetterAuth/go-better-auth/internal/crypto"
	gobetterauthtests "github.com/GoBetterAuth/go-better-auth/tests"
)

func TestValidateSession_Valid(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	// Create a test user first to satisfy foreign key constraint
	testUser := gobetterauthtests.CreateTestUser()
	err := repos.UserRepo.Create(testUser)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Create a session with the existing user
	testSession := gobetterauthtests.CreateTestSession()
	testSession.UserID = testUser.ID
	testSession.ExpiresAt = time.Now().Add(24 * time.Hour) // Make it valid
	repos.SessionRepo.Create(testSession)

	service := NewService(
		gobetterauthtests.CreateTestConfig(),
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	req := &ValidateSessionRequest{
		SessionToken: testSession.Token,
	}

	resp, err := service.ValidateSession(req)
	if err != nil {
		t.Fatalf("ValidateSession failed: %v", err)
	}

	if resp == nil {
		t.Fatal("ValidateSession returned nil response")
	}

	if !resp.Valid {
		t.Error("Expected session to be valid")
	}

	if resp.Session == nil {
		t.Error("Expected session to be set")
	}
}

func TestValidateSession_Expired(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	// Create a test user first to satisfy foreign key constraint
	testUser := gobetterauthtests.CreateTestUser()
	err := repos.UserRepo.Create(testUser)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Create an expired session with the existing user
	testSession := gobetterauthtests.CreateTestSession()
	testSession.UserID = testUser.ID
	testSession.ExpiresAt = time.Now().Add(-1 * time.Hour) // Make it expired
	repos.SessionRepo.Create(testSession)

	service := NewService(
		gobetterauthtests.CreateTestConfig(),
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	req := &ValidateSessionRequest{
		SessionToken: testSession.Token,
	}

	resp, err := service.ValidateSession(req)
	if err != nil {
		t.Fatalf("ValidateSession failed: %v", err)
	}

	if resp.Valid {
		t.Error("Expected session to be invalid due to expiration")
	}
}

func TestValidateSession_NotFound(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := NewService(
		gobetterauthtests.CreateTestConfig(),
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	req := &ValidateSessionRequest{
		SessionToken: "invalid-token",
	}

	resp, err := service.ValidateSession(req)
	if err != nil {
		t.Fatalf("ValidateSession failed: %v", err)
	}

	if resp.Valid {
		t.Error("Expected session to be invalid")
	}

	if resp.Session != nil {
		t.Error("Expected session to be nil")
	}
}

func TestRefreshToken_Valid(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	// Create a test user first to satisfy foreign key constraint
	testUser := gobetterauthtests.CreateTestUser()
	err := repos.UserRepo.Create(testUser)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	testSession := gobetterauthtests.CreateTestSession()
	testSession.UserID = testUser.ID
	testSession.ExpiresAt = time.Now().Add(24 * time.Hour)
	repos.SessionRepo.Create(testSession)

	service := NewService(
		gobetterauthtests.CreateTestConfig(),
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	oldToken := testSession.Token

	req := &RefreshTokenRequest{
		SessionToken: oldToken,
		IPAddress:    "192.168.1.2",
		UserAgent:    "Chrome",
	}

	resp, err := service.RefreshToken(req)
	if err != nil {
		t.Fatalf("RefreshToken failed: %v", err)
	}

	if resp.Session == nil {
		t.Fatal("RefreshToken returned nil session")
	}

	if resp.Session.Token == oldToken {
		t.Error("Expected token to be refreshed")
	}

	if resp.Session.ExpiresAt.Before(time.Now().Add(23 * time.Hour)) {
		t.Error("Expected session expiration to be refreshed")
	}

	oldSession, err := repos.SessionRepo.FindByToken(oldToken)
	if err != nil {
		t.Errorf("Unexpected error when checking old token: %v", err)
	}
	if oldSession != nil {
		t.Error("Expected old token to be invalid")
	}

	foundSession, err := repos.SessionRepo.FindByToken(resp.Session.Token)
	if err != nil || foundSession == nil {
		t.Error("Expected to find new session token")
	}
}

func TestRefreshToken_Expired(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	// Create a test user first to satisfy foreign key constraint
	testUser := gobetterauthtests.CreateTestUser()
	err := repos.UserRepo.Create(testUser)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	testSession := gobetterauthtests.CreateTestSession()
	testSession.UserID = testUser.ID
	testSession.ExpiresAt = time.Now().Add(-1 * time.Hour)
	repos.SessionRepo.Create(testSession)

	service := NewService(
		gobetterauthtests.CreateTestConfig(),
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	req := &RefreshTokenRequest{
		SessionToken: testSession.Token,
	}

	_, refreshErr := service.RefreshToken(req)
	if refreshErr == nil {
		t.Fatal("Expected error for expired session")
	}
}

func TestRequestPasswordReset_Valid(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	testUser := gobetterauthtests.CreateTestUser()
	repos.UserRepo.Create(testUser)

	service := NewService(
		gobetterauthtests.CreateTestConfig(),
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	req := &RequestPasswordResetRequest{
		Email: testUser.Email,
	}

	resp, err := service.RequestPasswordReset(context.Background(), req)
	if err != nil {
		t.Fatalf("RequestPasswordReset failed: %v", err)
	}

	if resp.Verification == nil {
		t.Fatal("RequestPasswordReset returned nil verification")
	}

	if resp.Verification.Type != verification.TypePasswordReset {
		t.Errorf("Expected verification type %s, got %s", verification.TypePasswordReset, resp.Verification.Type)
	}

	if resp.Verification.Identifier != testUser.Email {
		t.Errorf("Expected identifier %s, got %s", testUser.Email, resp.Verification.Identifier)
	}

	v, err := repos.VerificationRepo.FindByToken(resp.Verification.Token)
	if err != nil || v == nil {
		t.Error("Expected verification token to be stored")
	}
}

func TestResetPassword_Valid(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	testUser := gobetterauthtests.CreateTestUser()
	repos.UserRepo.Create(testUser)

	oldPassword := "OldPassword123!"
	hashedOldPassword, _ := crypto.HashPassword(oldPassword)
	testAccount := gobetterauthtests.CreateTestAccount(testUser.ID, &hashedOldPassword)
	repos.AccountRepo.Create(testAccount)

	resetToken := "reset-token-12345"
	hashedResetToken := crypto.HashVerificationToken(resetToken)
	v := &verification.Verification{
		UserID:     testUser.ID,
		Identifier: testUser.Email,
		Token:      hashedResetToken,
		Type:       verification.TypePasswordReset,
		ExpiresAt:  time.Now().Add(24 * time.Hour),
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	repos.VerificationRepo.Create(v)

	service := NewService(
		gobetterauthtests.CreateTestConfig(), repos.UserRepo, repos.SessionRepo, repos.AccountRepo, repos.VerificationRepo)

	req := &ResetPasswordRequest{
		Token:       resetToken,
		NewPassword: "NewPassword456!",
	}

	resp, err := service.ResetPassword(req)
	if err != nil {
		t.Fatalf("ResetPassword failed: %v", err)
	}

	if resp.Message != "Password has been reset successfully" {
		t.Error("Expected reset password to succeed")
	}

	updatedAccount, err := repos.AccountRepo.FindByID(testAccount.ID)
	if err != nil || updatedAccount == nil {
		t.Fatal("Failed to find updated account")
	}

	matches, err := crypto.VerifyPassword(oldPassword, *updatedAccount.Password)
	if err != nil || matches {
		t.Error("Old password should not match")
	}

	matches, err = crypto.VerifyPassword(req.NewPassword, *updatedAccount.Password)
	if err != nil || !matches {
		t.Error("New password should match")
	}

	_, err = repos.VerificationRepo.FindByHashedToken(resetToken)
	if err == nil {
		t.Error("Expected reset token to be deleted")
	}
}

func TestResetPassword_InvalidToken(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := NewService(
		gobetterauthtests.CreateTestConfig(),
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	req := &ResetPasswordRequest{
		Token:       "invalid-token",
		NewPassword: "NewPassword456!",
	}

	_, err := service.ResetPassword(req)
	if err == nil {
		t.Fatal("Expected error for invalid token")
	}
}

func TestSendEmailVerification_Valid(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	config := gobetterauthtests.CreateTestConfig()
	config.EmailVerification.Enabled = true

	service := NewService(
		config,
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	email := "verify@example.com"
	req := &SendEmailVerificationRequest{
		Email: email,
	}

	resp, err := service.SendEmailVerification(context.Background(), req)
	if err != nil {
		t.Fatalf("SendEmailVerification failed: %v", err)
	}

	if resp.Status == false {
		t.Fatal("SendEmailVerification returned false status")
	}
}

func TestVerifyEmail_Valid(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	testUser := gobetterauthtests.CreateTestUser()
	testUser.EmailVerified = false
	repos.UserRepo.Create(testUser)

	verificationToken := "verify-token-12345"
	hashedVerificationToken := crypto.HashVerificationToken(verificationToken)
	v := &verification.Verification{
		Identifier: testUser.Email,
		Token:      hashedVerificationToken,
		Type:       verification.TypeEmailVerification,
		ExpiresAt:  time.Now().Add(24 * time.Hour),
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	repos.VerificationRepo.Create(v)

	service := NewService(
		gobetterauthtests.CreateTestConfig(), repos.UserRepo, repos.SessionRepo, repos.AccountRepo, repos.VerificationRepo)

	req := &VerifyEmailRequest{
		VerificationToken: verificationToken,
	}

	resp, err := service.VerifyEmail(context.Background(), req)
	if err != nil {
		t.Fatalf("VerifyEmail failed: %v", err)
	}

	if resp == nil {
		t.Fatal("VerifyEmail returned nil response")
	}

	if !resp.Status {
		t.Fatal("VerifyEmail returned false status")
	}

	updatedUser, err := repos.UserRepo.FindByID(testUser.ID)
	if err != nil || updatedUser == nil {
		t.Fatal("Failed to find updated user")
	}

	if !updatedUser.EmailVerified {
		t.Error("Expected email to be verified")
	}

	_, err = repos.VerificationRepo.FindByHashedToken(verificationToken)
	if err == nil {
		t.Error("Expected verification token to be deleted")
	}
}

func TestVerifyEmail_ExpiredToken(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	expiredToken := "expired-verify-token"
	v := &verification.Verification{
		Identifier: "test@example.com",
		Token:      expiredToken,
		Type:       verification.TypeEmailVerification,
		ExpiresAt:  time.Now().Add(-1 * time.Hour),
		CreatedAt:  time.Now().Add(-2 * time.Hour),
		UpdatedAt:  time.Now().Add(-2 * time.Hour),
	}
	repos.VerificationRepo.Create(v)

	service := NewService(
		gobetterauthtests.CreateTestConfig(),
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	req := &VerifyEmailRequest{
		VerificationToken: expiredToken,
	}

	_, err := service.VerifyEmail(context.Background(), req)
	if err == nil {
		t.Fatal("Expected error for expired token")
	}
}

func TestGetProfile_Valid(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	testUser := gobetterauthtests.CreateTestUser()
	repos.UserRepo.Create(testUser)

	service := NewService(
		gobetterauthtests.CreateTestConfig(),
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	req := &GetMeRequest{
		UserID: testUser.ID,
	}

	resp, err := service.GetMe(req)
	if err != nil {
		t.Fatalf("GetProfile failed: %v", err)
	}

	if resp.User == nil {
		t.Fatal("GetProfile returned nil user")
	}

	if resp.User.ID != testUser.ID {
		t.Errorf("Expected user ID %s, got %s", testUser.ID, resp.User.ID)
	}

	if resp.User.Email != testUser.Email {
		t.Errorf("Expected email %s, got %s", testUser.Email, resp.User.Email)
	}
}

func TestGetProfile_NotFound(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := NewService(
		gobetterauthtests.CreateTestConfig(),
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	req := &GetMeRequest{
		UserID: "non-existent-id",
	}

	_, err := service.GetMe(req)
	if err == nil {
		t.Fatal("Expected error for non-existent user")
	}
}

func TestPasswordHasher_Default(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := NewService(
		gobetterauthtests.CreateTestConfig(),
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	password := "test-password-123"
	hash, err := service.passwordHasher.Hash(password)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	if hash == "" {
		t.Error("Expected non-empty hash")
	}

	valid, err := service.passwordHasher.Verify(password, hash)
	if err != nil {
		t.Fatalf("Failed to verify password: %v", err)
	}

	if !valid {
		t.Error("Expected password to be valid")
	}

	valid, err = service.passwordHasher.Verify("wrong-password", hash)
	if err != nil {
		t.Fatalf("Failed to verify wrong password: %v", err)
	}

	if valid {
		t.Error("Expected wrong password to be invalid")
	}
}

func TestPasswordHasher_Custom(t *testing.T) {
	customHash := func(password string) (string, error) {
		return "custom-hash-" + password, nil
	}

	customVerify := func(password, hash string) bool {
		expected := "custom-hash-" + password
		return hash == expected
	}

	config := gobetterauthtests.CreateTestConfig()
	config.EmailAndPassword = &domain.EmailPasswordConfig{
		Enabled: true,
		Password: &domain.PasswordConfig{
			Hash:   customHash,
			Verify: customVerify,
		},
	}

	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := NewService(
		config,
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	password := "test-password-123"
	hash, err := service.passwordHasher.Hash(password)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	expectedHash := "custom-hash-" + password
	if hash != expectedHash {
		t.Errorf("Expected hash %q, got %q", expectedHash, hash)
	}

	valid, err := service.passwordHasher.Verify(password, hash)
	if err != nil {
		t.Fatalf("Failed to verify password: %v", err)
	}

	if !valid {
		t.Error("Expected password to be valid")
	}

	valid, err = service.passwordHasher.Verify("wrong-password", hash)
	if err != nil {
		t.Fatalf("Failed to verify wrong password: %v", err)
	}

	if valid {
		t.Error("Expected wrong password to be invalid")
	}
}

func TestPasswordHasher_CustomHashOnly(t *testing.T) {
	customHash := func(password string) (string, error) {
		return "custom-hash-" + password, nil
	}

	config := gobetterauthtests.CreateTestConfig()
	config.EmailAndPassword = &domain.EmailPasswordConfig{
		Enabled: true,
		Password: &domain.PasswordConfig{
			Hash: customHash,
		},
	}

	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := NewService(
		config,
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)

	password := "test-password-123"
	hash, err := service.passwordHasher.Hash(password)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	if hash == "custom-hash-"+password {
		t.Error("Expected default hash, got custom hash")
	}
}
