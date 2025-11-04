package domain

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

// ValidationError represents a configuration validation error
type ValidationError struct {
	Field   string
	Message string
}

// ConfigValidationResult holds validation results
type ConfigValidationResult struct {
	Valid  bool
	Errors []ValidationError
}

// ValidateConfig validates the entire configuration
func ValidateConfig(config *Config) *ConfigValidationResult {
	result := &ConfigValidationResult{
		Valid:  true,
		Errors: []ValidationError{},
	}

	// Validate BaseURL
	if config.BaseURL == "" {
		result.AddError("BaseURL", "BaseURL is required")
	} else {
		if err := validateURL(config.BaseURL); err != nil {
			result.AddError("BaseURL", err.Error())
		}
	}

	// Validate Secret
	if config.Secret == "" {
		result.AddError("Secret", "Secret is required")
	} else if len(config.Secret) < 16 {
		result.AddError("Secret", "Secret must be at least 16 characters long")
	}

	// Validate Database config
	if err := validateDatabaseConfig(&config.Database); err != nil {
		result.AddError("Database", err.Error())
	}

	// Validate TrustedOrigins
	if err := validateTrustedOrigins(&config.TrustedOrigins); err != nil {
		result.AddError("TrustedOrigins", err.Error())
	}

	// Validate EmailVerification config
	if config.EmailVerification != nil {
		if err := validateEmailVerificationConfig(config.EmailVerification); err != nil {
			result.AddError("EmailVerification", err.Error())
		}
	}

	// Validate EmailAndPassword config
	if config.EmailAndPassword != nil {
		if err := validateEmailPasswordConfig(config.EmailAndPassword); err != nil {
			result.AddError("EmailAndPassword", err.Error())
		}
	}

	// Validate Session config
	if config.Session != nil {
		if err := validateSessionConfig(config.Session); err != nil {
			result.AddError("Session", err.Error())
		}
	}

	// Validate RateLimit config
	if config.RateLimit != nil {
		if err := validateRateLimitConfig(config.RateLimit); err != nil {
			result.AddError("RateLimit", err.Error())
		}
	}

	// Validate Advanced config
	if config.Advanced != nil {
		if err := validateAdvancedConfig(config.Advanced); err != nil {
			result.AddError("Advanced", err.Error())
		}
	}

	// Validate Logger config
	if config.Logger != nil {
		if err := validateLoggerConfig(config.Logger); err != nil {
			result.AddError("Logger", err.Error())
		}
	}

	if len(result.Errors) > 0 {
		result.Valid = false
	}

	return result
}

// AddError adds a validation error
func (r *ConfigValidationResult) AddError(field, message string) {
	r.Errors = append(r.Errors, ValidationError{
		Field:   field,
		Message: message,
	})
	r.Valid = false
}

// Error returns the error message for all validation errors
func (r *ConfigValidationResult) Error() string {
	if r.Valid {
		return ""
	}

	var messages []string
	for _, err := range r.Errors {
		messages = append(messages, fmt.Sprintf("%s: %s", err.Field, err.Message))
	}
	return "Configuration validation failed:\n  - " + strings.Join(messages, "\n  - ")
}

// validateURL validates a URL format
func validateURL(urlStr string) error {
	_, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("invalid URL format: %w", err)
	}
	return nil
}

// validateDatabaseConfig validates database configuration
func validateDatabaseConfig(config *DatabaseConfig) error {
	if config.Provider == "" {
		return fmt.Errorf("Provider is required")
	}

	provider := strings.ToLower(config.Provider)
	if provider != "sqlite" && provider != "postgres" {
		return fmt.Errorf("unsupported provider: %s (supported: sqlite, postgres)", provider)
	}

	if config.ConnectionString == "" {
		return fmt.Errorf("ConnectionString is required")
	}

	// Validate connection pool settings
	if config.MaxOpenConns < 0 {
		return fmt.Errorf("MaxOpenConns must be non-negative")
	}
	if config.MaxIdleConns < 0 {
		return fmt.Errorf("MaxIdleConns must be non-negative")
	}
	if config.ConnMaxLifetime < 0 {
		return fmt.Errorf("ConnMaxLifetime must be non-negative")
	}

	return nil
}

// validateTrustedOrigins validates trusted origins configuration
func validateTrustedOrigins(config *TrustedOriginsConfig) error {
	if config == nil {
		return nil
	}

	for _, origin := range config.StaticOrigins {
		if origin == "" {
			return fmt.Errorf("empty origin in StaticOrigins")
		}
		// Allow wildcards in origins
		if !strings.Contains(origin, "*") {
			if err := validateURL(origin); err != nil {
				return fmt.Errorf("invalid origin format: %s", origin)
			}
		}
	}

	return nil
}

// validateEmailVerificationConfig validates email verification configuration
func validateEmailVerificationConfig(config *EmailVerificationConfig) error {
	if config.ExpiresIn < 0 {
		return fmt.Errorf("ExpiresIn must be positive")
	}

	if config.ExpiresIn == 0 {
		return nil // Allows default
	}

	if config.ExpiresIn < 1*time.Minute {
		return fmt.Errorf("ExpiresIn should be at least 60 seconds")
	}

	return nil
}

// validateEmailPasswordConfig validates email/password authentication configuration
func validateEmailPasswordConfig(config *EmailPasswordConfig) error {
	if !config.Enabled {
		return nil
	}

	if config.MinPasswordLength < 4 {
		return fmt.Errorf("MinPasswordLength must be at least 4")
	}

	if config.MaxPasswordLength < config.MinPasswordLength {
		return fmt.Errorf("MaxPasswordLength must be >= MinPasswordLength")
	}

	if config.MaxPasswordLength > 512 {
		return fmt.Errorf("MaxPasswordLength is too large (max 512)")
	}

	if config.ResetPasswordTokenExpiresIn < 1*time.Minute {
		return fmt.Errorf("ResetPasswordTokenExpiresIn should be at least 1 minute")
	}

	return nil
}

// validateSessionConfig validates session configuration
func validateSessionConfig(config *SessionConfig) error {
	if config.ExpiresIn < 0 {
		return fmt.Errorf("ExpiresIn must be positive")
	}

	if config.ExpiresIn > 0 && config.ExpiresIn < 300 {
		return fmt.Errorf("ExpiresIn should be at least 300 seconds (5 minutes)")
	}

	if config.UpdateAge < 0 {
		return fmt.Errorf("UpdateAge must be positive")
	}

	if config.UpdateAge > 0 && config.UpdateAge < 60 {
		return fmt.Errorf("UpdateAge should be at least 60 seconds")
	}

	if config.UpdateAge > config.ExpiresIn && config.ExpiresIn > 0 {
		return fmt.Errorf("UpdateAge must be <= ExpiresIn")
	}

	if config.CookieCache != nil && config.CookieCache.MaxAge < 0 {
		return fmt.Errorf("CookieCache.MaxAge must be positive")
	}

	return nil
}

// validateRateLimitConfig validates rate limit configuration
func validateRateLimitConfig(config *RateLimitOptions) error {
	if !config.Enabled {
		return nil
	}

	if config.Window <= 0 {
		return fmt.Errorf("Window must be positive")
	}

	if config.Max <= 0 {
		return fmt.Errorf("Max must be positive")
	}

	if config.Algorithm != "" {
		algorithm := strings.ToLower(config.Algorithm)
		if algorithm != "fixed-window" && algorithm != "sliding-window" {
			return fmt.Errorf("invalid algorithm: %s (supported: fixed-window, sliding-window)", algorithm)
		}
	}

	if config.Storage != "" {
		storage := strings.ToLower(config.Storage)
		if storage != "memory" && storage != "database" && storage != "secondary-storage" {
			return fmt.Errorf("invalid storage: %s (supported: memory, database, secondary-storage)", storage)
		}
	}

	for path, rule := range config.CustomRules {
		if path == "" {
			return fmt.Errorf("empty path in CustomRules")
		}
		if rule.Window <= 0 {
			return fmt.Errorf("CustomRules[%s].Window must be positive", path)
		}
		if rule.Max <= 0 {
			return fmt.Errorf("CustomRules[%s].Max must be positive", path)
		}
	}

	return nil
}

// validateAdvancedConfig validates advanced configuration
func validateAdvancedConfig(config *AdvancedConfig) error {
	if config == nil {
		return nil
	}

	if config.CookiePrefix != "" {
		if len(config.CookiePrefix) > 50 {
			return fmt.Errorf("CookiePrefix is too long (max 50 characters)")
		}
		if strings.Contains(config.CookiePrefix, " ") {
			return fmt.Errorf("CookiePrefix cannot contain spaces")
		}
	}

	if config.CrossSubDomainCookies != nil {
		if config.CrossSubDomainCookies.Domain == "" {
			return fmt.Errorf("CrossSubDomainCookies.Domain is required when enabled")
		}
	}

	if config.Database != nil {
		if config.Database.DefaultFindManyLimit < 1 {
			return fmt.Errorf("Database.DefaultFindManyLimit must be at least 1")
		}
	}

	return nil
}

// validateLoggerConfig validates logger configuration
func validateLoggerConfig(config *LoggerConfig) error {
	if config == nil {
		return nil
	}

	validLevels := map[LogLevel]bool{
		LogLevelInfo:  true,
		LogLevelWarn:  true,
		LogLevelError: true,
		LogLevelDebug: true,
	}

	if config.Level != "" && !validLevels[config.Level] {
		return fmt.Errorf("invalid log level: %s (supported: info, warn, error, debug)", config.Level)
	}

	return nil
}
