package gobetterauth

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/GoBetterAuth/go-better-auth/domain"
	"github.com/GoBetterAuth/go-better-auth/domain/security"
	"github.com/GoBetterAuth/go-better-auth/domain/session"
	"github.com/GoBetterAuth/go-better-auth/handler"
	"github.com/GoBetterAuth/go-better-auth/infrastructure/migration"
	"github.com/GoBetterAuth/go-better-auth/middleware"
	"github.com/GoBetterAuth/go-better-auth/repository"
	"github.com/GoBetterAuth/go-better-auth/repository/cached"
	gormrepo "github.com/GoBetterAuth/go-better-auth/repository/gorm"
	"github.com/GoBetterAuth/go-better-auth/repository/memory"
	"github.com/GoBetterAuth/go-better-auth/repository/secondary"
	"github.com/GoBetterAuth/go-better-auth/storage"
	"github.com/GoBetterAuth/go-better-auth/usecase/auth"
	"github.com/GoBetterAuth/go-better-auth/usecase/ratelimit"
	"github.com/GoBetterAuth/go-better-auth/usecase/security_protection"
	"github.com/GoBetterAuth/go-better-auth/vault"
)

type Auth struct {
	config          *domain.Config
	secretGenerator *vault.SecretGenerator
	passwordHasher  *vault.Argon2PasswordHasher
	cipherManager   *vault.CipherManager
	repositories    *gormrepo.Repositories
	cookieManager   *handler.CookieManager
}

// New creates a new instance of the authentication system
func New(config *domain.Config) (*Auth, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	config.ApplyDefaults()

	validationResult := domain.ValidateConfig(config)
	if !validationResult.Valid {
		return nil, fmt.Errorf("invalid configuration: %s", validationResult.Error())
	}

	var cipherManager *vault.CipherManager
	if config.Secret != "" {
		cm, err := vault.NewCipherManager(config.Secret)
		if err != nil {
			return nil, fmt.Errorf("failed to create cipher manager: %w", err)
		}
		cipherManager = cm
	}

	repositories, err := createRepositories(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create repositories: %w", err)
	}

	cookieManager := handler.NewCookieManager(config)

	auth := &Auth{
		config:          config,
		secretGenerator: vault.NewSecretGenerator(),
		passwordHasher:  vault.NewArgon2PasswordHasher(),
		cipherManager:   cipherManager,
		repositories:    repositories,
		cookieManager:   cookieManager,
	}

	return auth, nil
}

// createRepositories creates GORM repositories based on configuration
func createRepositories(cfg *domain.Config) (*gormrepo.Repositories, error) {
	gormCfg := &gormrepo.Config{
		Provider:         strings.ToLower(cfg.Database.Provider),
		ConnectionString: cfg.Database.ConnectionString,
		LogQueries:       cfg.Database.LogQueries,
		MaxOpenConns:     cfg.Database.MaxOpenConns,
		MaxIdleConns:     cfg.Database.MaxIdleConns,
		ConnMaxLifetime:  cfg.Database.ConnMaxLifetime,
	}

	repositories, err := gormrepo.NewRepositories(gormCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create repositories: %w", err)
	}

	return repositories, nil
}

// Config returns the configuration
func (auth *Auth) Config() *domain.Config {
	return auth.config
}

// RunMigrations runs database migrations for the authentication system.
// This is primarily intended for testing environments where automatic
// migrations are needed.
func (auth *Auth) RunMigrations(ctx context.Context) error {
	if auth.repositories == nil {
		return fmt.Errorf("repositories not initialized")
	}

	provider := strings.ToLower(auth.config.Database.Provider)
	return migration.RunTestMigrations(auth.repositories.DB, provider)
}

// SecretGenerator returns the secret generator
func (auth *Auth) SecretGenerator() *vault.SecretGenerator {
	return auth.secretGenerator
}

// PasswordHasher returns the password hasher
func (auth *Auth) PasswordHasher() *vault.Argon2PasswordHasher {
	return auth.passwordHasher
}

// CipherManager returns the cipher manager for encryption and signing
func (auth *Auth) CipherManager() *vault.CipherManager {
	return auth.cipherManager
}

// Handler returns an http.Handler that implements all authentication endpoints.
// This handler can be mounted on any HTTP server, including Chi, Echo, and stdlib mux.
// The handler automatically includes CORS middleware configured with the trusted origins.
// If secondary storage is configured, it will be used for session caching and rate limiting.
func (a *Auth) Handler() http.Handler {
	userRepo := a.repositories.UserRepo
	accountRepo := a.repositories.AccountRepo
	verificationRepo := a.repositories.VerificationRepo

	// Wrap session repository with caching if secondary storage is available
	var sessionRepo session.Repository
	sessionRepo = a.repositories.SessionRepo
	if a.config.SecondaryStorage != nil {
		sessionRepo = cached.NewSessionRepository(sessionRepo, a.config.SecondaryStorage)
	}

	service := auth.NewService(
		a.config,
		userRepo,
		sessionRepo,
		accountRepo,
		verificationRepo,
	)

	if a.config.BruteForce != nil && a.config.BruteForce.Enabled {
		var bruteForceRepo security.BruteForceRepository
		if a.config.BruteForce.UseSecondaryStorage && a.config.SecondaryStorage != nil {
			bruteForceRepo = secondary.NewSecondaryStorageBruteForceRepository(a.config.SecondaryStorage)
		} else {
			bruteForceRepo = memory.NewInMemoryBruteForceRepository()
		}
		bruteForceService := security_protection.NewBruteForceService(bruteForceRepo, a.config.BruteForce)
		service.SetBruteForceService(bruteForceService)
	}

	cookieManager := handler.NewCookieManager(a.config)

	baseHandler := handler.NewAuthHandler(service, cookieManager)

	// Initialize OAuth if social providers are configured
	var oauthHandler *handler.OAuthHandler
	if a.config.SocialProviders != nil {
		providerRegistry := memory.NewOAuthProviderRegistry()
		stateManager, err := a.createOAuthStateManager()
		if err != nil {
			slog.Warn("failed to create OAuth state manager", "error", err)
		} else {
			if a.config.SocialProviders.Google != nil {
				googleProvider, err := repository.NewGoogleOAuthProvider(
					a.config.SocialProviders.Google.ClientID,
					a.config.SocialProviders.Google.ClientSecret,
					a.config.SocialProviders.Google.RedirectURI,
				)
				if err != nil {
					slog.Warn("failed to initialize Google OAuth provider", "error", err)
				} else {
					if err := providerRegistry.Register(googleProvider); err != nil {
						slog.Warn("failed to register Google OAuth provider", "error", err)
					}
				}
			}

			if a.config.SocialProviders.GitHub != nil {
				githubProvider, err := repository.NewGitHubOAuthProvider(
					a.config.SocialProviders.GitHub.ClientID,
					a.config.SocialProviders.GitHub.ClientSecret,
					a.config.SocialProviders.GitHub.RedirectURI,
				)
				if err != nil {
					slog.Warn("failed to initialize GitHub OAuth provider", "error", err)
				} else {
					if err := providerRegistry.Register(githubProvider); err != nil {
						slog.Warn("failed to register GitHub OAuth provider", "error", err)
					}
				}
			}

			if a.config.SocialProviders.Discord != nil {
				discordProvider, err := repository.NewDiscordOAuthProvider(
					a.config.SocialProviders.Discord.ClientID,
					a.config.SocialProviders.Discord.ClientSecret,
					a.config.SocialProviders.Discord.RedirectURI,
				)
				if err != nil {
					slog.Warn("failed to initialize Discord OAuth provider", "error", err)
				} else {
					if err := providerRegistry.Register(discordProvider); err != nil {
						slog.Warn("failed to register Discord OAuth provider", "error", err)
					}
				}
			}

			registeredProviders := providerRegistry.List()
			if len(registeredProviders) > 0 {
				oauthHandler = handler.NewOAuthHandler(service, stateManager, providerRegistry)
			}
		}
	}

	var handlerWithMiddleware http.Handler = baseHandler
	if a.config.RateLimit != nil && a.config.RateLimit.Enabled && a.config.SecondaryStorage != nil {
		limiter := ratelimit.NewLimiter(a.config.SecondaryStorage)
		rateLimitMW := middleware.RateLimitMiddleware(a.config, limiter)
		handlerWithMiddleware = rateLimitMW(baseHandler)
	}

	hooksMiddleware := middleware.HooksMiddleware(a.config)
	handlerWithMiddleware = hooksMiddleware(handlerWithMiddleware)

	if oauthHandler != nil {
		handlerWithMiddleware = a.composeWithOAuth(handlerWithMiddleware, oauthHandler)
	}

	if a.config.TrustedOrigins.StaticOrigins != nil || a.config.TrustedOrigins.DynamicOrigins != nil {
		corsMiddleware := middleware.NewCORSMiddleware(&a.config.TrustedOrigins)
		return corsMiddleware.Handler(handlerWithMiddleware)
	}

	return handlerWithMiddleware
}

// authService creates and returns the authentication service
// This is used internally by middleware factory methods
func (a *Auth) authService() *auth.Service {
	userRepo := a.repositories.UserRepo
	accountRepo := a.repositories.AccountRepo
	verificationRepo := a.repositories.VerificationRepo

	var sessionRepo session.Repository
	sessionRepo = a.repositories.SessionRepo
	if a.config.SecondaryStorage != nil {
		sessionRepo = cached.NewSessionRepository(sessionRepo, a.config.SecondaryStorage)
	}

	service := auth.NewService(
		a.config,
		userRepo,
		sessionRepo,
		accountRepo,
		verificationRepo,
	)

	if a.config.BruteForce != nil && a.config.BruteForce.Enabled {
		var bruteForceRepo security.BruteForceRepository
		if a.config.BruteForce.UseSecondaryStorage && a.config.SecondaryStorage != nil {
			bruteForceRepo = secondary.NewSecondaryStorageBruteForceRepository(a.config.SecondaryStorage)
		} else {
			bruteForceRepo = memory.NewInMemoryBruteForceRepository()
		}
		bruteForceService := security_protection.NewBruteForceService(bruteForceRepo, a.config.BruteForce)
		service.SetBruteForceService(bruteForceService)
	}

	return service
}

// createOAuthStateManager creates an OAuth state manager based on configuration
func (a *Auth) createOAuthStateManager() (*storage.OAuthStateManager, error) {
	config := a.config.SocialProviders.OAuthStateStorage

	// Set defaults if config is nil
	if config == nil {
		config = &domain.OAuthStateStorageConfig{
			Type:            "memory",
			CleanupInterval: 5 * time.Minute,
			TTL:             10 * time.Minute,
			KeyPrefix:       "oauth_state:",
		}
	}

	// Apply defaults for missing values
	if config.CleanupInterval <= 0 {
		config.CleanupInterval = 5 * time.Minute
	}
	if config.TTL <= 0 {
		config.TTL = 10 * time.Minute
	}
	if config.KeyPrefix == "" {
		config.KeyPrefix = "oauth_state:"
	}

	var oauthStorage storage.OAuthStateStorage
	var err error

	switch config.Type {
	case "database":
		if a.repositories == nil {
			return nil, fmt.Errorf("database storage requested but no repositories available")
		}
		db, dbErr := a.repositories.GetDB()
		if dbErr != nil || db == nil {
			return nil, fmt.Errorf("database storage requested but no database connection available: %w", dbErr)
		}
		oauthStorage, err = storage.NewDatabaseOAuthStateStorage(db, config.CleanupInterval)
		if err != nil {
			return nil, fmt.Errorf("failed to create database OAuth state storage: %w", err)
		}

	case "secondary":
		if a.config.SecondaryStorage == nil {
			return nil, fmt.Errorf("secondary storage requested but not configured")
		}
		oauthStorage = storage.NewSecondaryOAuthStateStorage(a.config.SecondaryStorage, config.KeyPrefix)

	case "memory", "":
		// Default to in-memory storage
		oauthStorage = storage.NewInMemoryOAuthStateStorage(config.CleanupInterval)

	default:
		return nil, fmt.Errorf("unsupported OAuth state storage type: %s", config.Type)
	}

	// Create the state manager with the configured storage
	stateManager, err := storage.NewOAuthStateManagerWithStorage(a.config.Secret, config.TTL, oauthStorage)
	if err != nil {
		return nil, fmt.Errorf("failed to create OAuth state manager: %w", err)
	}

	return stateManager, nil
}

// composeWithOAuth wraps the base handler with OAuth routing capability
// It creates a composite handler that delegates to either the base auth handler or OAuth handler
// based on the request path
func (auth *Auth) composeWithOAuth(baseHandler http.Handler, oauthHandler *handler.OAuthHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Check if this is an OAuth request
		// OAuth paths: /auth/oauth/{provider}, /auth/oauth/{provider}/callback, etc.
		if strings.Contains(path, "/oauth/") {
			oauthHandler.ServeHTTP(w, r)
			return
		}

		// Delegate to base handler for all other auth paths
		baseHandler.ServeHTTP(w, r)
	})
}

// AuthMiddleware returns a ready-to-use authentication middleware
// It validates session tokens and extracts user IDs from requests
// The middleware requires valid authentication (returns 401 if missing or invalid)
func (auth *Auth) AuthMiddleware() *middleware.AuthMiddleware {
	return middleware.NewAuthMiddleware(auth.authService(), auth.cookieManager.GetSessionCookieName())
}

// OptionalAuthMiddleware returns a ready-to-use optional authentication middleware
// It validates session tokens if present, but doesn't require them
// Requests without tokens or with invalid tokens are still allowed
func (auth *Auth) OptionalAuthMiddleware() *middleware.OptionalAuthMiddleware {
	return middleware.NewOptionalAuthMiddleware(auth.authService(), auth.cookieManager.GetSessionCookieName())
}
