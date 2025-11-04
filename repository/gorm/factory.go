package gorm

import (
	"context"
	"fmt"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/GoBetterAuth/go-better-auth/domain/account"
	"github.com/GoBetterAuth/go-better-auth/domain/session"
	"github.com/GoBetterAuth/go-better-auth/domain/user"
	"github.com/GoBetterAuth/go-better-auth/domain/verification"
)

// Config holds configuration for GORM repositories
type Config struct {
	// Database provider ("sqlite" or "postgres")
	Provider string

	// Connection string for the database
	ConnectionString string

	// Whether to log queries for debugging
	LogQueries bool

	// Maximum number of open database connections
	MaxOpenConns int

	// Maximum number of idle database connections
	MaxIdleConns int

	// Maximum lifetime for database connections (in seconds)
	ConnMaxLifetime int
}

// Repositories holds all GORM repository implementations
type Repositories struct {
	UserRepo         user.Repository
	SessionRepo      session.Repository
	AccountRepo      account.Repository
	VerificationRepo verification.Repository
	DB               *gorm.DB
}

// NewRepositories creates and initializes all GORM repositories with the given configuration
func NewRepositories(cfg *Config) (*Repositories, error) {
	if cfg == nil {
		return nil, fmt.Errorf("configuration cannot be nil")
	}

	if cfg.ConnectionString == "" {
		return nil, fmt.Errorf("connection string cannot be empty")
	}

	// Set default values
	if cfg.MaxOpenConns == 0 {
		cfg.MaxOpenConns = 25
	}
	if cfg.MaxIdleConns == 0 {
		cfg.MaxIdleConns = 5
	}
	if cfg.ConnMaxLifetime == 0 {
		cfg.ConnMaxLifetime = 3600 // 1 hour
	}

	// Create GORM database connection
	var db *gorm.DB
	var err error

	switch cfg.Provider {
	case "sqlite":
		db, err = gorm.Open(sqlite.Open(cfg.ConnectionString), &gorm.Config{})
	case "postgres":
		db, err = gorm.Open(postgres.Open(cfg.ConnectionString), &gorm.Config{})
	default:
		return nil, fmt.Errorf("unsupported database provider: %s", cfg.Provider)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Configure connection pool
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}

	sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)
	sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
	sqlDB.SetConnMaxLifetime(time.Duration(cfg.ConnMaxLifetime) * time.Second)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sqlDB.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Enable foreign keys for SQLite
	if cfg.Provider == "sqlite" {
		if _, err := sqlDB.Exec("PRAGMA foreign_keys = ON"); err != nil {
			return nil, fmt.Errorf("failed to enable foreign keys: %w", err)
		}
	}

	// Create repositories
	repos := &Repositories{
		UserRepo:         NewUserRepository(db, cfg.LogQueries),
		SessionRepo:      NewSessionRepository(db, cfg.LogQueries),
		AccountRepo:      NewAccountRepository(db, cfg.LogQueries),
		VerificationRepo: NewVerificationRepository(db, cfg.LogQueries),
		DB:               db,
	}

	return repos, nil
}

// Close closes the database connection
func (r *Repositories) Close() error {
	sqlDB, err := r.DB.DB()
	if err != nil {
		return fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}
	return sqlDB.Close()
}

// GetDB returns the underlying *gorm.DB connection
func (r *Repositories) GetDB() (*gorm.DB, error) {
	return r.DB, nil
}

// HealthCheck checks the database connection health
func (r *Repositories) HealthCheck(ctx context.Context) error {
	sqlDB, err := r.DB.DB()
	if err != nil {
		return fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}

	if err := sqlDB.PingContext(ctx); err != nil {
		return fmt.Errorf("database health check failed: %w", err)
	}

	return nil
}
