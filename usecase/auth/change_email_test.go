package auth

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/GoBetterAuth/go-better-auth/domain/user"
	gobetterauthtests "github.com/GoBetterAuth/go-better-auth/tests"
)

func TestChangeEmail(t *testing.T) {
	tests := []struct {
		name          string
		request       *ChangeEmailRequest
		setupUser     *user.User
		setupUsers    []*user.User
		expectedError string
		expectedMsg   string
	}{
		{
			name:          "nil request",
			request:       nil,
			expectedError: "change email request cannot be nil",
		},
		{
			name: "missing user ID",
			request: &ChangeEmailRequest{
				NewEmail: "newemail@example.com",
			},
			expectedError: "user ID is required",
		},
		{
			name: "missing new email",
			request: &ChangeEmailRequest{
				UserID: "user123",
			},
			expectedError: "new email is required",
		},
		{
			name: "invalid email format",
			request: &ChangeEmailRequest{
				UserID:   "user123",
				NewEmail: "invalid-email",
			},
			expectedError: "invalid email: invalid email format",
		},
		{
			name: "user not found",
			request: &ChangeEmailRequest{
				UserID:   "nonexistent",
				NewEmail: "newemail@example.com",
			},
			expectedError: "failed to find user: user not found",
		},
		{
			name: "new email same as current email",
			request: &ChangeEmailRequest{
				UserID:   "user123",
				NewEmail: "user@example.com",
			},
			setupUser: &user.User{
				ID:            "user123",
				Name:          "Test User",
				Email:         "user@example.com",
				EmailVerified: true,
				CreatedAt:     time.Now(),
				UpdatedAt:     time.Now(),
			},
			expectedError: "new email is the same as current email",
		},
		{
			name: "email already in use",
			request: &ChangeEmailRequest{
				UserID:   "user123",
				NewEmail: "other@example.com",
			},
			setupUser: &user.User{
				ID:            "user123",
				Name:          "Test User",
				Email:         "myemail@example.com",
				EmailVerified: true,
				CreatedAt:     time.Now(),
				UpdatedAt:     time.Now(),
			},
			setupUsers: []*user.User{
				{
					ID:            "user456",
					Name:          "Another User",
					Email:         "other@example.com",
					EmailVerified: true,
					CreatedAt:     time.Now(),
					UpdatedAt:     time.Now(),
				},
			},
			expectedError: "email is already in use",
		},
		{
			name: "successful request",
			request: &ChangeEmailRequest{
				UserID:   "user123",
				NewEmail: "newemail@example.com",
			},
			setupUser: &user.User{
				ID:            "user123",
				Name:          "Test User",
				Email:         "user@example.com",
				EmailVerified: true,
				CreatedAt:     time.Now(),
				UpdatedAt:     time.Now(),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
			defer cleanup()

			// Setup user with consistent ID
			testUserID := "test-user-id"
			if tt.setupUser != nil {
				tt.setupUser.ID = testUserID
				if err := repos.UserRepo.Create(tt.setupUser); err != nil {
					t.Fatalf("failed to setup user: %v", err)
				}
				// Update request with actual user ID
				if tt.request != nil && tt.request.UserID == "user123" {
					tt.request.UserID = testUserID
				}
			}

			// Setup additional users with different IDs
			for i, u := range tt.setupUsers {
				u.ID = "test-other-user-" + string(rune(i))
				if err := repos.UserRepo.Create(u); err != nil {
					t.Fatalf("failed to setup user: %v", err)
				}
			}

			svc := NewService(
				gobetterauthtests.CreateTestConfig(),
				repos.UserRepo,
				repos.SessionRepo,
				repos.AccountRepo,
				repos.VerificationRepo,
			)

			svc.config.User.ChangeEmail.Enabled = true

			resp, err := svc.ChangeEmail(context.Background(), tt.request)

			if tt.expectedError != "" {
				if err == nil || !strings.Contains(err.Error(), tt.expectedError) {
					t.Errorf("expected error containing %q, got %v", tt.expectedError, err)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if resp == nil {
				t.Errorf("expected response, got nil")
				return
			}

			if resp.Status != true {
				t.Errorf("expected status true, got false")
			}

			if resp.Message == "" {
				t.Errorf("expected message in response, got nil")
				return
			}
		})
	}
}
