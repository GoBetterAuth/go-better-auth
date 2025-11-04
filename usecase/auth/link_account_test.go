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

func TestLinkOAuthAccount_Success(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	ctx := context.Background()
	config := gobetterauthtests.CreateTestConfig()

	service := NewService(config, repos.UserRepo, repos.SessionRepo, repos.AccountRepo, repos.VerificationRepo)

	// Create a user
	newUser := gobetterauthtests.CreateTestUser()
	err := repos.UserRepo.Create(newUser)
	require.NoError(t, err)

	// Link OAuth account
	req := &LinkOAuthAccountRequest{
		UserID:      newUser.ID,
		ProviderID:  account.ProviderGoogle,
		AccountID:   "google-user-123",
		AccessToken: "access_token_123",
	}

	resp, err := service.LinkOAuthAccount(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.Account.ID)
	assert.Equal(t, req.UserID, resp.Account.UserID)
	assert.Equal(t, req.ProviderID, resp.Account.ProviderID)
	assert.Equal(t, req.AccountID, resp.Account.AccountID)
}

func TestLinkOAuthAccount_UserNotFound(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	ctx := context.Background()
	config := gobetterauthtests.CreateTestConfig()

	service := NewService(config, repos.UserRepo, repos.SessionRepo, repos.AccountRepo, repos.VerificationRepo)

	req := &LinkOAuthAccountRequest{
		UserID:      "non-existent-user",
		ProviderID:  account.ProviderGoogle,
		AccountID:   "google-user-123",
		AccessToken: "access_token_123",
	}

	resp, err := service.LinkOAuthAccount(ctx, req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "user not found")
}

func TestLinkOAuthAccount_AlreadyLinked(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	ctx := context.Background()
	config := gobetterauthtests.CreateTestConfig()

	service := NewService(config, repos.UserRepo, repos.SessionRepo, repos.AccountRepo, repos.VerificationRepo)

	// Create a user
	newUser := gobetterauthtests.CreateTestUser()
	err := repos.UserRepo.Create(newUser)
	require.NoError(t, err)

	// Link OAuth account first time
	req := &LinkOAuthAccountRequest{
		UserID:      newUser.ID,
		ProviderID:  account.ProviderGoogle,
		AccountID:   "google-user-123",
		AccessToken: "access_token_123",
	}

	resp, err := service.LinkOAuthAccount(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Try to link the same provider again
	resp, err = service.LinkOAuthAccount(ctx, req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "already linked")
}

func TestUnlinkOAuthAccount_Success(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	ctx := context.Background()
	config := gobetterauthtests.CreateTestConfig()

	service := NewService(config, repos.UserRepo, repos.SessionRepo, repos.AccountRepo, repos.VerificationRepo)

	// Create a user
	newUser := gobetterauthtests.CreateTestUser()
	err := repos.UserRepo.Create(newUser)
	require.NoError(t, err)

	// Link OAuth account
	linkReq := &LinkOAuthAccountRequest{
		UserID:      newUser.ID,
		ProviderID:  account.ProviderGoogle,
		AccountID:   "google-user-123",
		AccessToken: "access_token_123",
	}

	linkResp, err := service.LinkOAuthAccount(ctx, linkReq)
	require.NoError(t, err)
	require.NotNil(t, linkResp)

	// Unlink the account
	unlinkReq := &UnlinkOAuthAccountRequest{
		UserID:     newUser.ID,
		ProviderID: account.ProviderGoogle,
	}

	unlinkResp, err := service.UnlinkOAuthAccount(ctx, unlinkReq)
	require.NoError(t, err)
	assert.True(t, unlinkResp.Success)

	// Verify the account is deleted
	accounts, err := service.GetLinkedAccounts(ctx, newUser.ID)
	require.NoError(t, err)
	assert.Empty(t, accounts)
}

func TestUnlinkOAuthAccount_NotLinked(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	ctx := context.Background()
	config := gobetterauthtests.CreateTestConfig()

	service := NewService(config, repos.UserRepo, repos.SessionRepo, repos.AccountRepo, repos.VerificationRepo)

	// Create a user
	newUser := gobetterauthtests.CreateTestUser()
	err := repos.UserRepo.Create(newUser)
	require.NoError(t, err)

	// Try to unlink a non-existent account
	unlinkReq := &UnlinkOAuthAccountRequest{
		UserID:     newUser.ID,
		ProviderID: account.ProviderGoogle,
	}

	resp, err := service.UnlinkOAuthAccount(ctx, unlinkReq)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "not found")
}

func TestGetLinkedAccounts_Multiple(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	ctx := context.Background()
	config := gobetterauthtests.CreateTestConfig()

	service := NewService(config, repos.UserRepo, repos.SessionRepo, repos.AccountRepo, repos.VerificationRepo)

	// Create a user
	newUser := gobetterauthtests.CreateTestUser()
	err := repos.UserRepo.Create(newUser)
	require.NoError(t, err)

	// Link multiple OAuth accounts
	providers := []account.ProviderType{account.ProviderGoogle, account.ProviderGitHub, account.ProviderDiscord}

	for i, provider := range providers {
		req := &LinkOAuthAccountRequest{
			UserID:      newUser.ID,
			ProviderID:  provider,
			AccountID:   "account-" + string(rune('0'+i)),
			AccessToken: "token-" + string(rune('0'+i)),
		}

		resp, err := service.LinkOAuthAccount(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, resp)
	}

	// Get all linked accounts
	accounts, err := service.GetLinkedAccounts(ctx, newUser.ID)
	require.NoError(t, err)
	assert.Len(t, accounts, 3)

	// Verify all providers are present
	providerMap := make(map[account.ProviderType]bool)
	for _, acc := range accounts {
		providerMap[acc.ProviderID] = true
	}

	for _, provider := range providers {
		assert.True(t, providerMap[provider])
	}
}

func TestHasLinkedAccount_True(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	ctx := context.Background()
	config := gobetterauthtests.CreateTestConfig()

	service := NewService(config, repos.UserRepo, repos.SessionRepo, repos.AccountRepo, repos.VerificationRepo)

	// Create a user
	newUser := gobetterauthtests.CreateTestUser()
	err := repos.UserRepo.Create(newUser)
	require.NoError(t, err)

	// Link OAuth account
	linkReq := &LinkOAuthAccountRequest{
		UserID:      newUser.ID,
		ProviderID:  account.ProviderGoogle,
		AccountID:   "google-user-123",
		AccessToken: "access_token_123",
	}

	_, err = service.LinkOAuthAccount(ctx, linkReq)
	require.NoError(t, err)

	// Check if account exists
	has, err := service.HasLinkedAccount(ctx, newUser.ID, account.ProviderGoogle)
	require.NoError(t, err)
	assert.True(t, has)
}

func TestHasLinkedAccount_False(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	ctx := context.Background()
	config := gobetterauthtests.CreateTestConfig()

	service := NewService(config, repos.UserRepo, repos.SessionRepo, repos.AccountRepo, repos.VerificationRepo)

	// Create a user
	newUser := gobetterauthtests.CreateTestUser()
	err := repos.UserRepo.Create(newUser)
	require.NoError(t, err)

	// Check if account exists (should be false)
	has, err := service.HasLinkedAccount(ctx, newUser.ID, account.ProviderGoogle)
	require.NoError(t, err)
	assert.False(t, has)
}

func TestUpdateLinkedAccountTokens_Success(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	ctx := context.Background()
	config := gobetterauthtests.CreateTestConfig()

	service := NewService(config, repos.UserRepo, repos.SessionRepo, repos.AccountRepo, repos.VerificationRepo)

	// Create a user
	newUser := gobetterauthtests.CreateTestUser()
	err := repos.UserRepo.Create(newUser)
	require.NoError(t, err)

	// Link OAuth account
	linkReq := &LinkOAuthAccountRequest{
		UserID:      newUser.ID,
		ProviderID:  account.ProviderGoogle,
		AccountID:   "google-user-123",
		AccessToken: "access_token_123",
	}

	_, err = service.LinkOAuthAccount(ctx, linkReq)
	require.NoError(t, err)

	// Update tokens
	newAccessToken := "new_access_token_456"
	expiresAt := time.Now().Add(1 * time.Hour)
	err = service.UpdateLinkedAccountTokens(ctx, newUser.ID, account.ProviderGoogle, newAccessToken, nil, &expiresAt)
	require.NoError(t, err)

	// Verify the tokens were updated
	acc, err := repos.AccountRepo.FindByUserIDAndProvider(newUser.ID, account.ProviderGoogle)
	require.NoError(t, err)
	assert.Equal(t, newAccessToken, *acc.AccessToken)
	assert.WithinDuration(t, expiresAt, *acc.AccessTokenExpiresAt, time.Second)
}

func TestUpdateLinkedAccountTokens_NotFound(t *testing.T) {
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	ctx := context.Background()
	config := gobetterauthtests.CreateTestConfig()

	service := NewService(config, repos.UserRepo, repos.SessionRepo, repos.AccountRepo, repos.VerificationRepo)

	// Create a user
	newUser := gobetterauthtests.CreateTestUser()
	err := repos.UserRepo.Create(newUser)
	require.NoError(t, err)

	// Try to update tokens for a non-existent linked account
	err = service.UpdateLinkedAccountTokens(ctx, newUser.ID, account.ProviderGoogle, "new_token", nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}
