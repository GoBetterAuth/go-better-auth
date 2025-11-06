package auth

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/GoBetterAuth/go-better-auth/domain"
	"github.com/GoBetterAuth/go-better-auth/domain/user"
	"github.com/GoBetterAuth/go-better-auth/internal/crypto"
	gobetterauthtests "github.com/GoBetterAuth/go-better-auth/tests"
)

func TestRequestPasswordReset_SendsEmailWithVerifyEndpoint(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	testUser := gobetterauthtests.CreateTestUser()
	repos.UserRepo.Create(testUser)
	repos.AccountRepo.Create(gobetterauthtests.CreateTestAccount(testUser.ID, nil))

	config := gobetterauthtests.CreateTestConfig()
	config.BaseURL = "https://example.com"
	config.BasePath = "/auth"
	config.EmailAndPassword = &domain.EmailPasswordConfig{Enabled: true}

	done := make(chan struct{})
	var capturedURL string
	var capturedToken string
	var capturedUser *user.User

	config.EmailAndPassword.SendResetPassword = func(ctx context.Context, u *user.User, url string, token string) error {
		capturedURL = url
		capturedToken = token
		capturedUser = u
		close(done)
		return nil
	}

	service := NewService(config, repos.UserRepo, repos.SessionRepo, repos.AccountRepo, repos.VerificationRepo)

	callbackUrl := "https://app.example/reset-password"
	resp, err := service.RequestPasswordReset(context.Background(), &RequestPasswordResetRequest{
		Email:       testUser.Email,
		CallbackURL: &callbackUrl,
	})
	if err != nil {
		t.Fatalf("RequestPasswordReset returned error: %v", err)
	}

	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("expected SendResetPassword to be called")
	}

	if capturedUser == nil || capturedUser.ID != testUser.ID {
		t.Fatal("expected SendResetPassword to receive the test user")
	}

	if capturedToken == "" {
		t.Fatal("expected reset token to be provided")
	}

	if resp.Verification == nil {
		t.Fatal("expected verification to be returned")
	}

	// The stored token is the hashed version of the captured token
	if resp.Verification.Token != crypto.HashVerificationToken(capturedToken) {
		t.Fatal("expected verification token to be the hashed version of the captured token")
	}

	parsedURL, err := url.Parse(capturedURL)
	if err != nil {
		t.Fatalf("expected captured URL to be valid but got error: %v", err)
	}

	if parsedURL.Scheme != "https" || parsedURL.Host != "example.com" {
		t.Fatalf("expected URL host https://example.com but got %s://%s", parsedURL.Scheme, parsedURL.Host)
	}

	if parsedURL.Path != "/auth/verify-email" {
		t.Fatalf("expected URL path /auth/verify-email but got %s", parsedURL.Path)
	}

	query := parsedURL.Query()
	if query.Get("token") != capturedToken {
		t.Fatalf("expected token query param to match captured token but got %q", query.Get("token"))
	}

	if query.Get("callbackURL") != "https://app.example/reset-password" {
		t.Fatalf("expected callbackURL query param to be preserved but got %q", query.Get("callbackURL"))
	}
}

func TestRequestPasswordReset_UsesConfiguredExpiry(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	testUser := gobetterauthtests.CreateTestUser()
	repos.UserRepo.Create(testUser)

	config := gobetterauthtests.CreateTestConfig()
	config.EmailAndPassword = &domain.EmailPasswordConfig{
		Enabled:                     true,
		ResetPasswordTokenExpiresIn: 2 * time.Hour,
	}

	service := NewService(config, repos.UserRepo, repos.SessionRepo, repos.AccountRepo, repos.VerificationRepo)

	resp, err := service.RequestPasswordReset(context.Background(), &RequestPasswordResetRequest{Email: testUser.Email})
	if err != nil {
		t.Fatalf("RequestPasswordReset returned error: %v", err)
	}

	if resp.Verification == nil {
		t.Fatal("expected verification to be created")
	}

	expectedDuration := config.EmailAndPassword.ResetPasswordTokenExpiresIn
	actualDuration := resp.Verification.ExpiresAt.Sub(resp.Verification.CreatedAt)
	if actualDuration < 0 {
		actualDuration = -actualDuration
	}
	diff := actualDuration - expectedDuration
	if diff < 0 {
		diff = -diff
	}
	if diff > time.Millisecond {
		t.Fatalf("expected expiry duration ~%v but got %v", expectedDuration, resp.Verification.ExpiresAt.Sub(resp.Verification.CreatedAt))
	}
}
