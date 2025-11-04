package tests

import (
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/GoBetterAuth/go-better-auth/domain"
	"github.com/GoBetterAuth/go-better-auth/domain/account"
	"github.com/GoBetterAuth/go-better-auth/domain/session"
	"github.com/GoBetterAuth/go-better-auth/domain/user"
	"github.com/GoBetterAuth/go-better-auth/domain/verification"
	"github.com/GoBetterAuth/go-better-auth/infrastructure/migration"
	"github.com/GoBetterAuth/go-better-auth/repository/gorm"
)

func CreateTestConfig() *domain.Config {
	config := &domain.Config{}
	config.ApplyDefaults()
	return config
}

// CreateTestConfigWithDatabase creates a test config with an in-memory SQLite database
func CreateTestConfigWithDatabase() *domain.Config {
	return &domain.Config{
		BaseURL: "http://localhost:8080",
		Secret:  "very-secret-key-that-is-long-enough",
		Database: domain.DatabaseConfig{
			Provider:         "sqlite",
			ConnectionString: ":memory:",
		},
	}
}

// SetupTestAuth creates an auth instance with proper database setup and migrations
func SetupTestAuth(t *testing.T) (interface{}, func()) {
	// Setup structured logging for tests
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelError, // Reduce noise in tests
	}))
	slog.SetDefault(logger)

	config := CreateTestConfigWithDatabase()

	// Create repositories first
	gormCfg := &gorm.Config{
		Provider:         config.Database.Provider,
		ConnectionString: config.Database.ConnectionString,
		LogQueries:       config.Database.LogQueries,
	}

	repos, err := gorm.NewRepositories(gormCfg)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}

	// Run migrations
	err = RunTestMigrations(t, repos)
	if err != nil {
		repos.Close()
		t.Fatalf("failed to run test migrations: %v", err)
	}

	cleanup := func() {
		if err := repos.Close(); err != nil {
			t.Logf("failed to close repositories: %v", err)
		}
	}

	// Note: This function returns interface{} to avoid circular imports
	// The actual auth implementation should be created in the test file
	return config, cleanup
}

func CreateTestUser() *user.User {
	return &user.User{
		ID:            uuid.New().String(),
		Email:         "test@example.com",
		Name:          "Test User",
		EmailVerified: false,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
}

func CreateTestAccount(userID string, password *string) *account.Account {
	return &account.Account{
		ID:         uuid.New().String(),
		UserID:     userID,
		ProviderID: account.ProviderCredential,
		Password:   password,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
}

func CreateTestSession() *session.Session {
	return &session.Session{
		ID:        uuid.New().String(),
		UserID:    uuid.New().String(),
		Token:     uuid.New().String(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

type TestRepositories struct {
	UserRepo         user.Repository
	SessionRepo      session.Repository
	AccountRepo      account.Repository
	VerificationRepo verification.Repository
}

// RunTestMigrations runs migrations for testing using golang-migrate
func RunTestMigrations(t *testing.T, repos *gorm.Repositories) error {
	t.Helper()
	return migration.RunTestMigrations(repos.DB, "sqlite")
}

func SetupTestRepositories(t *testing.T) (*TestRepositories, func()) {
	cfg := &gorm.Config{
		Provider:         "sqlite",
		ConnectionString: ":memory:",
		LogQueries:       false,
	}

	repos, err := gorm.NewRepositories(cfg)
	if err != nil {
		t.Fatalf("failed to create test repositories: %v", err)
	}

	// Run migrations first
	err = RunTestMigrations(t, repos)
	if err != nil {
		t.Fatalf("failed to run test migrations: %v", err)
	}

	cleanup := func() {
		if err := repos.Close(); err != nil {
			t.Logf("failed to close test repositories: %v", err)
		}
	}

	testRepos := &TestRepositories{
		UserRepo:         repos.UserRepo,
		SessionRepo:      repos.SessionRepo,
		AccountRepo:      repos.AccountRepo,
		VerificationRepo: repos.VerificationRepo,
	}

	return testRepos, cleanup
}

// SetupTestSecondaryStorage creates a secondary storage instance with proper migrations for testing
func SetupTestSecondaryStorage(t *testing.T) (interface{}, func()) {
	cfg := &gorm.Config{
		Provider:         "sqlite",
		ConnectionString: ":memory:",
		LogQueries:       false,
	}

	repos, err := gorm.NewRepositories(cfg)
	if err != nil {
		t.Fatalf("failed to create test repositories: %v", err)
	}

	// Run migrations first
	err = RunTestMigrations(t, repos)
	if err != nil {
		t.Fatalf("failed to run test migrations: %v", err)
	}

	cleanup := func() {
		if err := repos.Close(); err != nil {
			t.Logf("failed to close test repositories: %v", err)
		}
	}

	// Return the DB instance instead of creating secondary storage here
	// to avoid circular imports
	return repos.DB, cleanup
}
