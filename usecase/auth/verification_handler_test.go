package auth

import (
	"context"
	"testing"
	"time"

	"github.com/GoBetterAuth/go-better-auth/domain/user"
	"github.com/GoBetterAuth/go-better-auth/domain/verification"
	gobetterauthtests "github.com/GoBetterAuth/go-better-auth/tests"
	"github.com/GoBetterAuth/go-better-auth/vault"
)

func TestVerifyEmailUnified(t *testing.T) {
	tests := []struct {
		name               string
		request            *VerifyEmailRequest
		setupUser          *user.User
		setupVerif         *verification.Verification
		expectedError      string
		setupUsers         []*user.User
		expectedEmailAfter string
	}{
		{
			name:          "nil request",
			request:       nil,
			expectedError: "verify email request cannot be nil",
		},
		{
			name:          "missing verification token",
			request:       &VerifyEmailRequest{},
			expectedError: "verification token is required",
		},
		{
			name: "invalid verification token",
			request: &VerifyEmailRequest{
				VerificationToken: "invalid",
			},
			expectedError: "failed to find verification token: verification not found",
		},
		{
			name: "expired email verification token",
			request: &VerifyEmailRequest{
				VerificationToken: "expired_token",
			},
			setupUser: &user.User{
				ID:            "user123",
				Name:          "Test User",
				Email:         "user@example.com",
				EmailVerified: false,
				CreatedAt:     time.Now(),
				UpdatedAt:     time.Now(),
			},
			setupVerif: &verification.Verification{
				ID:         "verif1",
				Identifier: "user@example.com",
				Token:      "expired_token",
				Type:       verification.TypeEmailVerification,
				ExpiresAt:  time.Now().Add(-1 * time.Hour),
				CreatedAt:  time.Now(),
				UpdatedAt:  time.Now(),
			},
			expectedError: "verification token has expired",
		},
		{
			name: "successful email verification",
			request: &VerifyEmailRequest{
				VerificationToken: "valid_email_verify_token",
			},
			setupUser: &user.User{
				ID:            "user123",
				Name:          "Test User",
				Email:         "user@example.com",
				EmailVerified: false,
				CreatedAt:     time.Now(),
				UpdatedAt:     time.Now(),
			},
			setupVerif: &verification.Verification{
				ID:         "verif1",
				Identifier: "user@example.com",
				Token:      "valid_email_verify_token",
				Type:       verification.TypeEmailVerification,
				ExpiresAt:  time.Now().Add(24 * time.Hour),
				CreatedAt:  time.Now(),
				UpdatedAt:  time.Now(),
			},
		},
		{
			name: "email change verification",
			request: &VerifyEmailRequest{
				VerificationToken: "valid_email_change_token",
			},
			setupUser: &user.User{
				ID:            "user123",
				Name:          "Test User",
				Email:         "oldemail@example.com",
				EmailVerified: true,
				CreatedAt:     time.Now(),
				UpdatedAt:     time.Now(),
			},
			setupVerif: &verification.Verification{
				ID:         "verif2",
				UserID:     "user123",
				Identifier: "newemail@example.com",
				Token:      "valid_email_change_token",
				Type:       verification.TypeEmailChange,
				ExpiresAt:  time.Now().Add(24 * time.Hour),
				CreatedAt:  time.Now(),
				UpdatedAt:  time.Now(),
			},
			expectedEmailAfter: "newemail@example.com",
		},
		{
			name: "email change with existing email",
			request: &VerifyEmailRequest{
				VerificationToken: "conflict_token",
			},
			setupVerif: &verification.Verification{
				ID:         "verif3",
				Identifier: "other@example.com",
				Token:      "conflict_token",
				Type:       verification.TypeEmailChange,
				ExpiresAt:  time.Now().Add(24 * time.Hour),
				CreatedAt:  time.Now(),
				UpdatedAt:  time.Now(),
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
			name: "password reset verification",
			request: &VerifyEmailRequest{
				VerificationToken: "valid_password_reset_token",
			},
			setupUser: &user.User{
				ID:            "user123",
				Name:          "Test User",
				Email:         "user@example.com",
				EmailVerified: true,
				CreatedAt:     time.Now(),
				UpdatedAt:     time.Now(),
			},
			setupVerif: &verification.Verification{
				ID:         "verif4",
				Identifier: "user@example.com",
				Token:      "valid_password_reset_token",
				Type:       verification.TypePasswordReset,
				ExpiresAt:  time.Now().Add(24 * time.Hour),
				CreatedAt:  time.Now(),
				UpdatedAt:  time.Now(),
			},
		},
		{
			name: "user not found for email verification",
			request: &VerifyEmailRequest{
				VerificationToken: "user_not_found_token",
			},
			setupVerif: &verification.Verification{
				ID:         "verif5",
				Identifier: "nonexistent@example.com",
				Token:      "user_not_found_token",
				Type:       verification.TypeEmailVerification,
				ExpiresAt:  time.Now().Add(24 * time.Hour),
				CreatedAt:  time.Now(),
				UpdatedAt:  time.Now(),
			},
			expectedError: "failed to find user: user not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
			defer cleanup()

			// Setup user if provided
			if tt.setupUser != nil {
				repos.UserRepo.Create(tt.setupUser)
			}

			// Setup verification if provided
			if tt.setupVerif != nil {
				// Keep the original plain token for the request and assertions
				plainToken := tt.setupVerif.Token
				// Create a copy for storing with hashed token
				verificationToStore := *tt.setupVerif
				verificationToStore.Token = vault.HashVerificationToken(plainToken)
				repos.VerificationRepo.Create(&verificationToStore)
			}

			// Setup additional users
			for _, u := range tt.setupUsers {
				repos.UserRepo.Create(u)
			}

			svc := &Service{
				config:           gobetterauthtests.CreateTestConfig(),
				userRepo:         repos.UserRepo,
				accountRepo:      repos.AccountRepo,
				sessionRepo:      repos.SessionRepo,
				verificationRepo: repos.VerificationRepo,
			}

			ctx := context.Background()
			resp, err := svc.VerifyEmail(ctx, tt.request)

			if tt.expectedError != "" {
				if err == nil {
					t.Fatalf("expected error %q but got nil", tt.expectedError)
				}
				if err.Error() != tt.expectedError {
					t.Fatalf("expected error %q but got %q", tt.expectedError, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error but got %q", err.Error())
				}

				if resp == nil {
					t.Fatal("expected response but got nil")
				}

				if !resp.Status {
					t.Fatal("expected status to be true")
				}

				if tt.setupVerif != nil && resp.Type != tt.setupVerif.Type {
					t.Fatalf("expected response type %q but got %q", tt.setupVerif.Type, resp.Type)
				}

				// For email verification, check that user's email is now verified
				if tt.setupVerif != nil && tt.setupVerif.Type == verification.TypeEmailVerification && tt.setupUser != nil {
					updatedUser, _ := repos.UserRepo.FindByEmail(tt.setupUser.Email)
					if updatedUser == nil {
						t.Fatal("user not found after verification")
					}
					if !updatedUser.EmailVerified {
						t.Fatal("email should be verified after verification")
					}
				}

				// For email change, check that email was updated and token is deleted
				if tt.setupVerif != nil && tt.setupVerif.Type == verification.TypeEmailChange {
					if tt.expectedEmailAfter != "" {
						updatedUser, _ := repos.UserRepo.FindByEmail(tt.expectedEmailAfter)
						if updatedUser == nil {
							t.Fatal("user not found with new email after email change verification")
						}
						if updatedUser.Email != tt.expectedEmailAfter {
							t.Fatalf("expected email to be %q but got %q", tt.expectedEmailAfter, updatedUser.Email)
						}
					}
				}

				if tt.setupVerif != nil && tt.setupVerif.Type == verification.TypeEmailChange {
					tokenAfter, _ := repos.VerificationRepo.FindByHashedToken(tt.setupVerif.Token)
					if tokenAfter != nil {
						t.Fatal("verification token should be deleted after verification")
					}
				}

				if tt.setupVerif != nil && tt.setupVerif.Type == verification.TypePasswordReset {
					if resp.Token == "" {
						t.Fatal("expected reset token in response")
					}

					expectedHashedToken := vault.HashVerificationToken(tt.setupVerif.Token)
					if resp.Token != expectedHashedToken {
						t.Fatalf("expected reset token to match hashed version")
					}

					tokenAfter, _ := repos.VerificationRepo.FindByHashedToken(tt.setupVerif.Token)
					if tokenAfter == nil {
						t.Fatal("verification token should remain for password reset")
					}
				}
			}
		})
	}
}
