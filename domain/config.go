package domain

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/GoBetterAuth/go-better-auth/domain/security"
	"github.com/GoBetterAuth/go-better-auth/domain/user"
	"github.com/GoBetterAuth/go-better-auth/storage"
)

// Config is the main configuration struct for Go Better Auth
type Config struct {
	// AppName is the name of the application
	AppName string

	// BaseURL is the base URL for Better Auth (e.g., "https://example.com")
	// If not set, will check GO_BETTER_AUTH_URL environment variable
	BaseURL string

	// BasePath is the base path for Better Auth routes (default: "/api/auth")
	// Will be overridden if there is a path component within BaseURL
	BasePath string

	// TrustedOrigins is a list of trusted origins for CORS
	// Supports static origins, dynamic origins via function, and wildcard patterns
	TrustedOrigins TrustedOriginsConfig

	// Secret is used for encryption, signing, and hashing
	// If not set, will check GO_BETTER_AUTH_SECRET or AUTH_SECRET environment variables
	// In production, if not set, will throw an error
	Secret string

	// Database configuration
	Database DatabaseConfig

	// Secondary Storage
	SecondaryStorage storage.SecondaryStorage

	// EmailAndPassword authentication configuration
	EmailAndPassword *EmailPasswordConfig

	// EmailVerification configuration
	EmailVerification *EmailVerificationConfig

	// SocialProviders configuration
	SocialProviders *SocialProvidersConfig

	// Plugins is a list of Better Auth plugins
	Plugins []Plugin

	// User configuration options
	User *UserConfig

	// Session configuration options
	Session *SessionConfig

	// Account configuration options
	Account *AccountConfig

	// Verification configuration options
	Verification *VerificationConfig

	// RateLimit configuration
	RateLimit *RateLimitOptions

	// BruteForce configuration
	BruteForce *security.BruteForceConfig

	// Advanced configuration options
	Advanced *AdvancedConfig

	// Logger configuration
	Logger *LoggerConfig

	// DatabaseHooks for lifecycle events
	DatabaseHooks *DatabaseHooksConfig

	// OnAPIError configuration
	OnAPIError *OnAPIErrorConfig

	// Hooks for request lifecycle
	Hooks *HooksConfig

	// DisabledPaths is a list of paths to disable
	DisabledPaths []string
}

// TrustedOriginsConfig can be a static list, dynamic function, or support wildcards
type TrustedOriginsConfig struct {
	// StaticOrigins is a static list of trusted origins
	StaticOrigins []string

	// DynamicOrigins is a function that returns origins dynamically based on the request
	DynamicOrigins func(r *http.Request) []string
}

// IsOriginTrusted checks if the given origin is trusted.
// It supports static origins, dynamic origins via callback, and wildcard patterns.
// Returns true if the origin is trusted, false otherwise.
func (c *TrustedOriginsConfig) IsOriginTrusted(origin string, r *http.Request) bool {
	if c == nil || origin == "" {
		return false
	}

	// Check static origins
	if len(c.StaticOrigins) > 0 {
		if isOriginInList(origin, c.StaticOrigins) {
			return true
		}
	}

	// Check dynamic origins if provided and request is available
	if c.DynamicOrigins != nil && r != nil {
		dynamicOrigins := c.DynamicOrigins(r)
		if isOriginInList(origin, dynamicOrigins) {
			return true
		}
	}

	return false
}

// isOriginInList checks if an origin is in a list of origins.
// Supports exact match and wildcard patterns.
func isOriginInList(origin string, origins []string) bool {
	for _, trustedOrigin := range origins {
		if matchesOriginPattern(origin, trustedOrigin) {
			return true
		}
	}
	return false
}

// matchesOriginPattern checks if an origin matches a pattern.
// Supports wildcard patterns like "https://*.example.com"
func matchesOriginPattern(origin string, pattern string) bool {
	// Exact match
	if origin == pattern {
		return true
	}

	// Wildcard pattern matching
	if !matchWildcardPattern(origin, pattern) {
		return false
	}

	return true
}

// matchWildcardPattern performs wildcard pattern matching for origins.
// Example patterns:
//   - "https://*.example.com" matches "https://app.example.com"
//   - "https://*.example.com" matches "https://api.example.com"
//   - "https://*" matches any HTTPS origin
func matchWildcardPattern(origin string, pattern string) bool {
	if !strings.Contains(pattern, "*") {
		return false
	}

	// Split pattern on first wildcard
	parts := strings.SplitN(pattern, "*", 2)
	prefix := parts[0]
	suffix := ""
	if len(parts) > 1 {
		suffix = parts[1]
	}

	// Check prefix
	if prefix != "" && !strings.HasPrefix(origin, prefix) {
		return false
	}

	origin = origin[len(prefix):]

	// Check suffix
	if suffix != "" && !strings.HasSuffix(origin, suffix) {
		return false
	}

	return true
}

// DatabaseConfig holds database configuration
type DatabaseConfig struct {
	// Provider is the database option ("sqlite", "postgres")
	Provider string

	// ConnectionString is the database connection string
	ConnectionString string

	// LogQueries enables SQL query logging for debugging (default: false)
	LogQueries bool

	// MaxOpenConns sets the maximum number of open connections to the database (default: 25)
	MaxOpenConns int

	// MaxIdleConns sets the maximum number of idle connections (default: 5)
	MaxIdleConns int

	// ConnMaxLifetime sets the maximum amount of time a connection may be reused in seconds (default: 3600)
	ConnMaxLifetime int
}

// RedisConfig holds Redis configuration for secondary storage
type RedisConfig struct {
	// Host is the Redis server host (default: "localhost")
	Host string

	// Port is the Redis server port (default: 6379)
	Port int

	// DB is the Redis database number (default: 0)
	DB int

	// Password is the Redis password (optional)
	Password string

	// TLS enables TLS connection to Redis (default: false)
	TLS bool

	// MaxRetries is the maximum number of retries (default: 3)
	MaxRetries int

	// PoolSize is the connection pool size (default: 10)
	PoolSize int
}

// EmailVerificationConfig holds email verification configuration
type EmailVerificationConfig struct {
	// Enabled enables email verification feature (default: false)
	Enabled bool

	// SendVerificationEmail is a function to send verification emails
	SendVerificationEmail func(ctx context.Context, user *user.User, url string, token string) error

	// SendOnSignUp automatically sends verification email after sign up (default: false)
	SendOnSignUp bool

	// SendOnSignIn sends verification email on sign in when user's email is not verified (default: false)
	SendOnSignIn bool

	// AutoSignInAfterVerification automatically signs in the user after email verification
	AutoSignInAfterVerification bool

	// ExpiresIn is the duration the verification token is valid for (default: 1 hour)
	ExpiresIn time.Duration
}

// PasswordConfig holds custom password hashing and verification
type PasswordConfig struct {
	// Hash is a custom password hashing function
	Hash func(password string) (string, error)

	// Verify is a custom password verification function
	Verify func(password, hash string) bool
}

// EmailPasswordConfig holds email/password auth configuration
type EmailPasswordConfig struct {
	// Enabled enables email and password authentication (default: false)
	Enabled bool

	// DisableSignUp disables email and password sign up (default: false)
	DisableSignUp bool

	// RequireEmailVerification requires email verification before session creation
	RequireEmailVerification bool

	// MinPasswordLength is the minimum password length (default: 8)
	MinPasswordLength int

	// MaxPasswordLength is the maximum password length (default: 128)
	MaxPasswordLength int

	// AutoSignIn automatically signs in the user after sign up
	AutoSignIn bool

	// SendResetPassword is a function to send reset password emails
	SendResetPassword func(ctx context.Context, user *user.User, url string, token string) error

	// ResetPasswordTokenExpiresIn is the duration the reset token is valid for (default: 1 hour)
	ResetPasswordTokenExpiresIn time.Duration

	// Password holds custom password hashing and verification functions
	Password *PasswordConfig
}

// SocialProvidersConfig holds social provider configuration
type SocialProvidersConfig struct {
	Google  *GoogleProviderConfig
	GitHub  *GitHubProviderConfig
	Discord *DiscordProviderConfig
}

// GoogleProviderConfig holds Google OAuth configuration
type GoogleProviderConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
}

// GitHubProviderConfig holds GitHub OAuth configuration
type GitHubProviderConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
}

// DiscordProviderConfig holds Discord OAuth configuration
type DiscordProviderConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
}

// Plugin defines the interface for Go Better Auth plugins
type Plugin interface {
	Name() string
	Initialize(config any) error
}

// AdditionalField defines an additional field for a model
type AdditionalField struct {
	Type string
	// Add more field properties as needed
}

// ChangeEmailConfig holds change email configuration
type ChangeEmailConfig struct {
	// Enabled enables the change email feature (default: false)
	Enabled bool

	// SendChangeEmailVerification is a function to send change email verification
	SendChangeEmailVerification func(ctx context.Context, user *user.User, newEmail string, url string, token string) error
}

// DeleteUserConfig holds user deletion configuration
type DeleteUserConfig struct {
	// Enabled enables the delete user feature (default: false)
	Enabled bool

	// SendDeleteAccountVerification is a function to send delete account verification
	SendDeleteAccountVerification func(ctx context.Context, user *user.User, url string, token string) error

	// BeforeDelete is called before user deletion
	BeforeDelete func(ctx context.Context, user *user.User) error

	// AfterDelete is called after user deletion
	AfterDelete func(ctx context.Context, user *user.User) error
}

// UserConfig holds user configuration options
type UserConfig struct {
	// ModelName is the model name for the user (default: "user")
	ModelName string

	// Fields maps field names to different column names
	Fields map[string]string

	// AdditionalFields defines additional fields for the user table
	AdditionalFields map[string]AdditionalField

	// ChangeEmail configuration
	ChangeEmail *ChangeEmailConfig

	// DeleteUser configuration
	DeleteUser *DeleteUserConfig
}

// CookieCacheConfig holds cookie cache configuration
type CookieCacheConfig struct {
	// Enabled enables caching session in cookie (default: false)
	Enabled bool

	// MaxAge is the cache duration in seconds (default: 300 - 5 minutes)
	MaxAge int
}

// SessionConfig holds session configuration
type SessionConfig struct {
	// ModelName is the model name for the session (default: "session")
	ModelName string

	// Fields maps field names to different column names
	Fields map[string]string

	// ExpiresIn is the expiration time for the session token in seconds (default: 604800 - 7 days)
	ExpiresIn time.Duration

	// UpdateAge is how often the session should be refreshed in seconds (default: 86400 - 1 day)
	UpdateAge time.Duration

	// DisableSessionRefresh disables session refresh (default: false)
	DisableSessionRefresh bool

	// AdditionalFields defines additional fields for the session table
	AdditionalFields map[string]AdditionalField

	// StoreSessionInDatabase stores session in database when secondary storage is provided (default: false)
	StoreSessionInDatabase bool

	// PreserveSessionInDatabase preserves session records in database when deleted from secondary storage (default: false)
	PreserveSessionInDatabase bool

	// CookieCache enables caching session in cookie
	CookieCache *CookieCacheConfig
}

// AccountLinkingConfig holds account linking configuration
type AccountLinkingConfig struct {
	// Enabled enables account linking (default: false)
	Enabled bool

	// TrustedProviders is a list of trusted providers
	TrustedProviders []string

	// AllowDifferentEmails allows users to link accounts with different email addresses
	AllowDifferentEmails bool

	// AllowUnlinkingAll allows users to unlink all accounts
	AllowUnlinkingAll bool
}

// AccountConfig holds account configuration options
type AccountConfig struct {
	// ModelName is the model name for the account
	ModelName string

	// Fields maps field names to different column names
	Fields map[string]string

	// EncryptOAuthTokens encrypts OAuth tokens before storing them (default: false)
	EncryptOAuthTokens bool

	// UpdateAccountOnSignIn updates account data on sign in with latest data from provider
	UpdateAccountOnSignIn bool

	// AccountLinking configuration
	AccountLinking *AccountLinkingConfig
}

// VerificationConfig holds verification configuration options
type VerificationConfig struct {
	// ModelName is the model name for the verification table
	ModelName string

	// Fields maps field names to different column names
	Fields map[string]string

	// DisableCleanup disables cleaning up expired values when a verification value is fetched
	DisableCleanup bool
}

// RateLimitRule defines a custom rate limit rule
type RateLimitRule struct {
	Window int
	Max    int
}

// RateLimitOptions holds rate limiting configuration options
type RateLimitOptions struct {
	// Enabled enables rate limiting (defaults: true in production, false in development)
	Enabled bool

	// Window is the time window in seconds (default: 10)
	Window int

	// Max is the maximum number of requests allowed within the window (default: 100)
	Max int

	// Algorithm specifies the rate limiting algorithm to use
	// Options: "fixed-window" (default), "sliding-window"
	// Fixed window: Simple counter that resets at window boundaries
	// Sliding window: Weighted counter using current and previous window for smoother limiting
	Algorithm string

	// CustomRules defines custom rate limit rules for specific paths
	CustomRules map[string]RateLimitRule

	// Storage defines the storage type ("memory", "database", "secondary-storage")
	Storage string

	// ModelName is the name of the table for rate limiting if database is used (default: "rateLimit")
	ModelName string
}

// IPAddressConfig holds IP address configuration
type IPAddressConfig struct {
	// IPAddressHeaders is a list of headers to check for IP address
	IPAddressHeaders []string

	// DisableIpTracking disables IP tracking
	DisableIpTracking bool
}

// CrossSubDomainCookiesConfig holds cross subdomain cookie configuration
type CrossSubDomainCookiesConfig struct {
	// Enabled enables cross subdomain cookies
	Enabled bool

	// AdditionalCookies is a list of additional cookies to share across subdomains
	AdditionalCookies []string

	// Domain is the domain for the cookies
	Domain string
}

// CookieAttributes holds cookie attributes
type CookieAttributes struct {
	HTTPOnly bool
	Secure   bool
	SameSite string
	Path     string
	Domain   string
	MaxAge   int
}

// CookieConfig holds cookie configuration
type CookieConfig struct {
	Name       string
	Attributes CookieAttributes
}

// DatabaseAdvancedConfig holds advanced database configuration
type DatabaseAdvancedConfig struct {
	// UseNumberId uses auto-incrementing IDs instead of UUIDs
	UseNumberId bool

	// GenerateId is a custom ID generator function, or false to disable ID generation
	GenerateId interface{} // func(model string, size int) string or false

	// DefaultFindManyLimit is the default limit for findMany queries
	DefaultFindManyLimit int
}

// AdvancedConfig holds advanced configuration options
type AdvancedConfig struct {
	// IPAddress configuration for rate limiting and session tracking
	IPAddress *IPAddressConfig

	// UseSecureCookies uses secure cookies (default: false)
	UseSecureCookies bool

	// DisableCSRFCheck disables trusted origins check (⚠️ security risk)
	DisableCSRFCheck bool

	// CrossSubDomainCookies configures cookies to be shared across subdomains
	CrossSubDomainCookies *CrossSubDomainCookiesConfig

	// Cookies allows customizing cookie names and attributes
	Cookies map[string]CookieConfig

	// DefaultCookieAttributes sets default attributes for all cookies
	DefaultCookieAttributes *CookieAttributes

	// CookiePrefix is a prefix for all cookies
	CookiePrefix string

	// Database holds advanced database configuration
	Database *DatabaseAdvancedConfig
}

// LogLevel defines the log level
type LogLevel string

const (
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"
	LogLevelDebug LogLevel = "debug"
)

// LoggerConfig holds logger configuration
type LoggerConfig struct {
	// Disabled disables all logging (default: false)
	Disabled bool

	// DisableColors disables colors in the default logger (default: auto-detected)
	DisableColors bool

	// Level is the minimum log level to display
	Level LogLevel

	// Log is a custom logging function
	Log func(level LogLevel, message string, args ...any)
}

// ModelHooks holds before/after hooks for a model
type ModelHooks struct {
	Create *CRUDHooks
	Update *CRUDHooks
}

// CRUDHooks holds before/after hooks for CRUD operations
type CRUDHooks struct {
	Before func(ctx context.Context, data interface{}) (interface{}, error)
	After  func(ctx context.Context, result interface{}) error
}

// DatabaseHooksConfig holds database lifecycle hooks
type DatabaseHooksConfig struct {
	User         *ModelHooks
	Session      *ModelHooks
	Account      *ModelHooks
	Verification *ModelHooks
}

// OnAPIErrorConfig holds API error handling configuration
type OnAPIErrorConfig struct {
	// Throw throws an error on API error (default: false)
	Throw bool

	// OnError is a custom error handler
	OnError func(err error, ctx context.Context)

	// ErrorURL is the URL to redirect to on error (default: "/api/auth/error")
	ErrorURL string
}

// RequestContext holds request context information passed to hooks.
// Users can read all properties to understand the request and optionally
// modify fields by returning a new context object from hook functions.
type RequestContext struct {
	// Path is the URL path of the request (e.g., "/auth/signin")
	Path string
	// Method is the HTTP method of the request (GET, POST, etc.)
	Method string
	// Body contains the parsed request body (for POST/PUT requests)
	Body any
	// Headers contains the request headers
	Headers map[string][]string
	// Query contains query parameters from the URL
	Query map[string][]string
	// Request is the underlying *http.Request object
	Request *http.Request
	// Context contains auth-related context like session, config, etc.
	Context map[string]any
}

// HookResponse is returned by hook functions to modify the request context.
// If the hook returns nil, the original context is used.
type HookResponse struct {
	// Context contains the modified context to be merged with the original
	Context *RequestContext
}

// HooksConfig holds request lifecycle hooks
type HooksConfig struct {
	// Before is executed before processing the request.
	// It receives the request context and can return a modified context.
	// If it returns an error, the request is blocked.
	Before func(ctx *RequestContext) (*HookResponse, error)

	// After is executed after processing the request.
	// It receives the request context and can return a modified context.
	// Errors are silently handled to avoid disrupting responses.
	After func(ctx *RequestContext) (*HookResponse, error)
}
