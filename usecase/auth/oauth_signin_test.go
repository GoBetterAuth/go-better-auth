package auth

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/GoBetterAuth/go-better-auth/domain/account"
	gobetterauthtests "github.com/GoBetterAuth/go-better-auth/tests"
)

func TestOAuthSignIn_NewUser(t *testing.T) {
	ctx := context.Background()
	config := gobetterauthtests.CreateTestConfig()

	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := NewService(config, repos.UserRepo, repos.SessionRepo, repos.AccountRepo, repos.VerificationRepo)

	// OAuth signin with new user
	pictureURL := "https://example.com/photo.jpg"
	expiresAt := time.Now().Add(1 * time.Hour)

	req := &OAuthSignInRequest{
		ProviderID: account.ProviderGoogle,
		OAuthUser: &account.OAuthUser{
			ID:      "google-123",
			Email:   "newuser@example.com",
			Name:    "New User",
			Picture: &pictureURL,
		},
		OAuthTokens: &account.OAuthTokens{
			AccessToken:          "access_token_123",
			RefreshToken:         strPtr("refresh_token_456"),
			IDToken:              strPtr("id_token_789"),
			AccessTokenExpiresAt: &expiresAt,
			Scope:                "email profile",
		},
	}

	resp, err := service.OAuthSignIn(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Verify new user was created
	assert.True(t, resp.IsNewUser)
	assert.NotEmpty(t, resp.User.ID)
	assert.Equal(t, "newuser@example.com", resp.User.Email)
	assert.Equal(t, "New User", resp.User.Name)
	assert.Equal(t, &pictureURL, resp.User.Image)
	assert.True(t, resp.User.EmailVerified)

	// Verify account was linked
	assert.NotEmpty(t, resp.Account.ID)
	assert.Equal(t, resp.User.ID, resp.Account.UserID)
	assert.Equal(t, account.ProviderGoogle, resp.Account.ProviderID)
	assert.Equal(t, "google-123", resp.Account.AccountID)

	// Verify session was created
	assert.NotEmpty(t, resp.Session.ID)
	assert.Equal(t, resp.User.ID, resp.Session.UserID)
	assert.NotEmpty(t, resp.Session.Token)
}

func TestOAuthSignIn_ExistingUser(t *testing.T) {
	ctx := context.Background()
	config := gobetterauthtests.CreateTestConfig()

	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := NewService(config, repos.UserRepo, repos.SessionRepo, repos.AccountRepo, repos.VerificationRepo)

	// Create existing user first via signup
	signupReq := &SignUpRequest{
		Email:    "existinguser@example.com",
		Password: "SecurePassword123!",
		Name:     "Existing User",
	}

	signupResp, err := service.SignUp(context.Background(), signupReq)
	require.NoError(t, err)

	// OAuth signin with existing user
	pictureURL := "https://example.com/photo.jpg"
	expiresAt := time.Now().Add(1 * time.Hour)

	req := &OAuthSignInRequest{
		ProviderID: account.ProviderGoogle,
		OAuthUser: &account.OAuthUser{
			ID:      "google-456",
			Email:   "existinguser@example.com",
			Name:    "Existing User Updated",
			Picture: &pictureURL,
		},
		OAuthTokens: &account.OAuthTokens{
			AccessToken:          "access_token_123",
			AccessTokenExpiresAt: &expiresAt,
			Scope:                "email profile",
		},
	}

	resp, err := service.OAuthSignIn(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Verify existing user was found
	assert.False(t, resp.IsNewUser)
	assert.Equal(t, signupResp.User.ID, resp.User.ID)
	assert.Equal(t, "existinguser@example.com", resp.User.Email)

	// Verify account was linked
	assert.NotEmpty(t, resp.Account.ID)
	assert.Equal(t, resp.User.ID, resp.Account.UserID)
	assert.Equal(t, account.ProviderGoogle, resp.Account.ProviderID)

	// Verify session was created
	assert.NotEmpty(t, resp.Session.ID)
	assert.Equal(t, resp.User.ID, resp.Session.UserID)
}

func TestOAuthSignIn_ExistingUserExistingAccount(t *testing.T) {
	ctx := context.Background()
	config := gobetterauthtests.CreateTestConfig()

	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := NewService(config, repos.UserRepo, repos.SessionRepo, repos.AccountRepo, repos.VerificationRepo)

	// First OAuth signin - creates user and account
	pictureURL := "https://example.com/photo.jpg"
	expiresAt := time.Now().Add(1 * time.Hour)

	req1 := &OAuthSignInRequest{
		ProviderID: account.ProviderGoogle,
		OAuthUser: &account.OAuthUser{
			ID:      "google-789",
			Email:   "user@example.com",
			Name:    "User Name",
			Picture: &pictureURL,
		},
		OAuthTokens: &account.OAuthTokens{
			AccessToken:          "access_token_old",
			RefreshToken:         strPtr("refresh_token_old"),
			AccessTokenExpiresAt: &expiresAt,
			Scope:                "email profile",
		},
	}

	resp1, err := service.OAuthSignIn(ctx, req1)
	require.NoError(t, err)
	require.True(t, resp1.IsNewUser)

	// Second OAuth signin - same user and provider, should update tokens
	newExpiresAt := time.Now().Add(2 * time.Hour)

	req2 := &OAuthSignInRequest{
		ProviderID: account.ProviderGoogle,
		OAuthUser: &account.OAuthUser{
			ID:      "google-789",
			Email:   "user@example.com",
			Name:    "User Name Updated",
			Picture: &pictureURL,
		},
		OAuthTokens: &account.OAuthTokens{
			AccessToken:          "access_token_new",
			RefreshToken:         strPtr("refresh_token_new"),
			AccessTokenExpiresAt: &newExpiresAt,
			Scope:                "email profile openid",
		},
	}

	resp2, err := service.OAuthSignIn(ctx, req2)
	require.NoError(t, err)
	require.False(t, resp2.IsNewUser)

	// Verify same user and account
	assert.Equal(t, resp1.User.ID, resp2.User.ID)
	assert.Equal(t, resp1.Account.ID, resp2.Account.ID)

	// Verify tokens were updated
	assert.Equal(t, "access_token_new", *resp2.Account.AccessToken)
	assert.Equal(t, "refresh_token_new", *resp2.Account.RefreshToken)
	assert.Equal(t, "email profile openid", *resp2.Account.Scope)

	// Verify new session was created
	assert.NotEqual(t, resp1.Session.ID, resp2.Session.ID)
}

func TestOAuthSignIn_NilRequest(t *testing.T) {
	ctx := context.Background()
	config := gobetterauthtests.CreateTestConfig()

	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := NewService(config, repos.UserRepo, repos.SessionRepo, repos.AccountRepo, repos.VerificationRepo)

	resp, err := service.OAuthSignIn(ctx, nil)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "request cannot be nil")
}

func TestOAuthSignIn_EmptyProviderID(t *testing.T) {
	ctx := context.Background()
	config := gobetterauthtests.CreateTestConfig()

	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := NewService(config, repos.UserRepo, repos.SessionRepo, repos.AccountRepo, repos.VerificationRepo)

	req := &OAuthSignInRequest{
		ProviderID: "",
		OAuthUser: &account.OAuthUser{
			ID:    "google-123",
			Email: "user@example.com",
			Name:  "Test User",
		},
		OAuthTokens: &account.OAuthTokens{
			AccessToken: "token",
			Scope:       "email",
		},
	}

	resp, err := service.OAuthSignIn(ctx, req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "provider_id cannot be empty")
}

func TestOAuthSignIn_NilOAuthUser(t *testing.T) {
	ctx := context.Background()
	config := gobetterauthtests.CreateTestConfig()

	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := NewService(config, repos.UserRepo, repos.SessionRepo, repos.AccountRepo, repos.VerificationRepo)

	req := &OAuthSignInRequest{
		ProviderID:  account.ProviderGoogle,
		OAuthUser:   nil,
		OAuthTokens: &account.OAuthTokens{AccessToken: "token", Scope: "email"},
	}

	resp, err := service.OAuthSignIn(ctx, req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "oauth_user cannot be nil")
}

func TestOAuthSignIn_EmptyEmail(t *testing.T) {
	ctx := context.Background()
	config := gobetterauthtests.CreateTestConfig()

	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := NewService(config, repos.UserRepo, repos.SessionRepo, repos.AccountRepo, repos.VerificationRepo)

	req := &OAuthSignInRequest{
		ProviderID: account.ProviderGoogle,
		OAuthUser: &account.OAuthUser{
			ID:    "google-123",
			Email: "",
			Name:  "Test User",
		},
		OAuthTokens: &account.OAuthTokens{AccessToken: "token", Scope: "email"},
	}

	resp, err := service.OAuthSignIn(ctx, req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "email cannot be empty")
}

func TestOAuthSignIn_MultipleProviders(t *testing.T) {
	ctx := context.Background()
	config := gobetterauthtests.CreateTestConfig()

	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := NewService(config, repos.UserRepo, repos.SessionRepo, repos.AccountRepo, repos.VerificationRepo)

	// Sign in with Google first
	googleReq := &OAuthSignInRequest{
		ProviderID: account.ProviderGoogle,
		OAuthUser: &account.OAuthUser{
			ID:    "google-123",
			Email: "user@example.com",
			Name:  "Test User",
		},
		OAuthTokens: &account.OAuthTokens{AccessToken: "google_token", Scope: "email"},
	}

	googleResp, err := service.OAuthSignIn(ctx, googleReq)
	require.NoError(t, err)
	require.True(t, googleResp.IsNewUser)

	// Sign in with GitHub (same email)
	githubReq := &OAuthSignInRequest{
		ProviderID: account.ProviderGitHub,
		OAuthUser: &account.OAuthUser{
			ID:    "github-456",
			Email: "user@example.com",
			Name:  "Test User",
		},
		OAuthTokens: &account.OAuthTokens{AccessToken: "github_token", Scope: "user"},
	}

	githubResp, err := service.OAuthSignIn(ctx, githubReq)
	require.NoError(t, err)
	require.False(t, githubResp.IsNewUser)

	// Verify same user
	assert.Equal(t, googleResp.User.ID, githubResp.User.ID)

	// Verify different accounts
	assert.NotEqual(t, googleResp.Account.ID, githubResp.Account.ID)
	assert.Equal(t, account.ProviderGoogle, googleResp.Account.ProviderID)
	assert.Equal(t, account.ProviderGitHub, githubResp.Account.ProviderID)

	// Verify user has both accounts linked
	linkedAccounts, err := service.GetLinkedAccounts(ctx, googleResp.User.ID)
	require.NoError(t, err)
	assert.Len(t, linkedAccounts, 2)
}

// Helper function
func strPtr(s string) *string {
	return &s
}
