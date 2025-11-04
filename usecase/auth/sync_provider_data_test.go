package auth

import (
	"context"
	"testing"

	"github.com/GoBetterAuth/go-better-auth/domain/account"
	gobetterauthtests "github.com/GoBetterAuth/go-better-auth/tests"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSyncProviderData_UpdateUserProfile(t *testing.T) {
	ctx := context.Background()
	config := gobetterauthtests.CreateTestConfig()

	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := NewService(config, repos.UserRepo, repos.SessionRepo, repos.AccountRepo, repos.VerificationRepo)

	// Create a user via SignUp to ensure proper ID generation
	signupResp, err := service.SignUp(ctx, &SignUpRequest{
		Email:    "user@example.com",
		Password: "ValidPassword123!",
		Name:     "Old Name",
	})
	require.NoError(t, err)
	require.NotNil(t, signupResp)

	newUser := signupResp.User

	// Link OAuth account
	linkReq := &LinkOAuthAccountRequest{
		UserID:      newUser.ID,
		ProviderID:  account.ProviderGoogle,
		AccountID:   "google-123",
		AccessToken: "token-123",
	}

	_, err = service.LinkOAuthAccount(ctx, linkReq)
	require.NoError(t, err)

	// Sync provider data with new name and picture
	pictureURL := "https://example.com/photo.jpg"
	syncReq := &SyncProviderDataRequest{
		UserID:     newUser.ID,
		ProviderID: account.ProviderGoogle,
		OAuthUser: &account.OAuthUser{
			ID:      "google-123",
			Email:   "user@example.com",
			Name:    "New Name",
			Picture: &pictureURL,
		},
		UpdateUser: true,
	}

	resp, err := service.SyncProviderData(ctx, syncReq)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, "New Name", resp.User.Name)
	assert.Equal(t, &pictureURL, resp.User.Image)
	assert.True(t, resp.Changes["name"])
	assert.True(t, resp.Changes["image"])
}

func TestSyncProviderData_NoChanges(t *testing.T) {
	ctx := context.Background()
	config := gobetterauthtests.CreateTestConfig()

	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := NewService(config, repos.UserRepo, repos.SessionRepo, repos.AccountRepo, repos.VerificationRepo)

	// Create a user via SignUp to ensure proper ID generation
	signupResp, err := service.SignUp(ctx, &SignUpRequest{
		Email:    "user@example.com",
		Password: "ValidPassword123!",
		Name:     "Test User",
	})
	require.NoError(t, err)
	require.NotNil(t, signupResp)

	newUser := signupResp.User

	// Link OAuth account
	linkReq := &LinkOAuthAccountRequest{
		UserID:      newUser.ID,
		ProviderID:  account.ProviderGoogle,
		AccountID:   "google-123",
		AccessToken: "token-123",
	}

	_, err = service.LinkOAuthAccount(ctx, linkReq)
	require.NoError(t, err)

	// Sync provider data with same info
	syncReq := &SyncProviderDataRequest{
		UserID:     newUser.ID,
		ProviderID: account.ProviderGoogle,
		OAuthUser: &account.OAuthUser{
			ID:    "google-123",
			Email: "user@example.com",
			Name:  "Test User",
		},
		UpdateUser: true,
	}

	resp, err := service.SyncProviderData(ctx, syncReq)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Should not have name or image changes
	assert.False(t, resp.Changes["name"])
	assert.False(t, resp.Changes["image"])
}

func TestSyncProviderData_LinkedAccountNotFound(t *testing.T) {
	ctx := context.Background()
	config := gobetterauthtests.CreateTestConfig()

	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := NewService(config, repos.UserRepo, repos.SessionRepo, repos.AccountRepo, repos.VerificationRepo)

	// Create a user without linking an account via SignUp to ensure proper ID generation
	signupResp, err := service.SignUp(ctx, &SignUpRequest{
		Email:    "user@example.com",
		Password: "ValidPassword123!",
		Name:     "Test User",
	})
	require.NoError(t, err)
	require.NotNil(t, signupResp)

	newUser := signupResp.User

	// Try to sync provider data for a non-existent linked account
	syncReq := &SyncProviderDataRequest{
		UserID:     newUser.ID,
		ProviderID: account.ProviderGoogle,
		OAuthUser: &account.OAuthUser{
			ID:   "google-123",
			Name: "Test User",
		},
		UpdateUser: true,
	}

	resp, err := service.SyncProviderData(ctx, syncReq)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "linked account not found")
}

func TestSyncProviderData_UserNotFound(t *testing.T) {
	ctx := context.Background()
	config := gobetterauthtests.CreateTestConfig()

	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := NewService(config, repos.UserRepo, repos.SessionRepo, repos.AccountRepo, repos.VerificationRepo)

	// Try to sync provider data for a non-existent user
	syncReq := &SyncProviderDataRequest{
		UserID:     "non-existent",
		ProviderID: account.ProviderGoogle,
		OAuthUser: &account.OAuthUser{
			ID:   "google-123",
			Name: "Test User",
		},
		UpdateUser: true,
	}

	resp, err := service.SyncProviderData(ctx, syncReq)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "user not found")
}

func TestSyncMultipleProvidersData(t *testing.T) {
	ctx := context.Background()
	config := gobetterauthtests.CreateTestConfig()

	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	service := NewService(config, repos.UserRepo, repos.SessionRepo, repos.AccountRepo, repos.VerificationRepo)

	// Create a user via SignUp to ensure proper ID generation
	signupResp, err := service.SignUp(ctx, &SignUpRequest{
		Email:    "user@example.com",
		Password: "ValidPassword123!",
		Name:     "Old Name",
	})
	require.NoError(t, err)
	require.NotNil(t, signupResp)

	newUser := signupResp.User

	// Link multiple OAuth accounts
	providers := map[account.ProviderType]string{
		account.ProviderGoogle:  "google-123",
		account.ProviderGitHub:  "github-456",
		account.ProviderDiscord: "discord-789",
	}

	for provider, accountID := range providers {
		linkReq := &LinkOAuthAccountRequest{
			UserID:      newUser.ID,
			ProviderID:  provider,
			AccountID:   accountID,
			AccessToken: "token-" + accountID,
		}

		_, err = service.LinkOAuthAccount(ctx, linkReq)
		require.NoError(t, err)
	}

	// Prepare provider data
	pictureURL := "https://example.com/photo.jpg"
	providerData := map[account.ProviderType]*account.OAuthUser{
		account.ProviderGoogle: {
			ID:      "google-123",
			Email:   "user@example.com",
			Name:    "Google Name",
			Picture: &pictureURL,
		},
		account.ProviderGitHub: {
			ID:   "github-456",
			Name: "GitHub User",
		},
		account.ProviderDiscord: {
			ID:   "discord-789",
			Name: "Discord User",
		},
	}

	// Sync multiple providers
	resp, err := service.SyncMultipleProvidersData(ctx, newUser.ID, providerData)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Verify user was updated from one of the providers
	// Since map iteration order is not guaranteed, we can't predict which provider will be first
	// But we know the name should be from one of the providers and not the original "Old Name"
	assert.NotEqual(t, "Old Name", resp.User.Name)
	validNames := []string{"Google Name", "GitHub User", "Discord User"}
	assert.Contains(t, validNames, resp.User.Name)

	// Image should only be set if Google provider was processed first (since it's the only one with a picture)
	if resp.User.Name == "Google Name" {
		assert.Equal(t, &pictureURL, resp.User.Image)
	} else {
		// Other providers don't have pictures, so image should remain nil
		assert.Nil(t, resp.User.Image)
	}
}

func TestMergeProviderProfiles(t *testing.T) {
	pictureURL1 := "https://example.com/photo1.jpg"
	pictureURL2 := "https://example.com/photo2.jpg"

	profile1 := &account.OAuthUser{
		ID:      "user-123",
		Email:   "user@example.com",
		Name:    "User Name",
		Picture: &pictureURL1,
	}

	profile2 := &account.OAuthUser{
		ID:      "user-456",
		Email:   "different@example.com",
		Name:    "",
		Picture: &pictureURL2,
	}

	profile3 := &account.OAuthUser{
		ID:   "user-789",
		Name: "Another Name",
	}

	// Merge profiles - first one should take precedence for non-empty fields
	merged := MergeProviderProfiles(profile1, profile2, profile3)

	assert.Equal(t, "user-123", merged.ID)
	assert.Equal(t, "user@example.com", merged.Email)
	assert.Equal(t, "User Name", merged.Name)
	assert.Equal(t, &pictureURL1, merged.Picture)
}

func TestMergeProviderProfiles_NilProfiles(t *testing.T) {
	profile1 := &account.OAuthUser{
		ID:   "user-123",
		Name: "User Name",
	}

	// Should handle nil profiles gracefully
	merged := MergeProviderProfiles(nil, profile1, nil)

	assert.Equal(t, "user-123", merged.ID)
	assert.Equal(t, "User Name", merged.Name)
}

func TestGetProviderUserEmail(t *testing.T) {
	oauthUser := &account.OAuthUser{
		ID:    "user-123",
		Email: "user@example.com",
		Name:  "Test User",
	}

	email := GetProviderUserEmail(oauthUser)
	assert.Equal(t, "user@example.com", email)

	// Test with nil
	email = GetProviderUserEmail(nil)
	assert.Empty(t, email)
}

func TestGetProviderUserName(t *testing.T) {
	oauthUser := &account.OAuthUser{
		ID:   "user-123",
		Name: "Test User",
	}

	name := GetProviderUserName(oauthUser)
	assert.Equal(t, "Test User", name)

	// Test with nil
	name = GetProviderUserName(nil)
	assert.Empty(t, name)
}

func TestGetProviderUserPicture(t *testing.T) {
	pictureURL := "https://example.com/photo.jpg"
	oauthUser := &account.OAuthUser{
		ID:      "user-123",
		Picture: &pictureURL,
	}

	picture := GetProviderUserPicture(oauthUser)
	assert.Equal(t, &pictureURL, picture)

	// Test with nil
	picture = GetProviderUserPicture(nil)
	assert.Nil(t, picture)
}
