# Go Better Auth 🔐

A comprehensive, framework-agnostic authentication and authorization library for Go.

**Note:** This project is still a work in progress. Contributions are most welcome!

## ✨ Features

- 🔑 **Email & Password Authentication** – Secure, production-ready authentication with argon2 password hashing
- 🌐 **Social OAuth Providers** – Google, GitHub, Discord, and extensible generic OAuth2 support
- 🔐 **Session Management** – Secure, customizable session handling with refresh and expiration controls
- ✉️ **Email Verification** – Optional, configurable email verification workflow
- 🔄 **Password Reset** – Secure password reset with customizable email callbacks
- 🏗️ **Clean Architecture** – Go Clean Architecture: domain, usecase, repository, handler, and infrastructure layers
- 🔌 **Plugin System** – Extensible plugin architecture for custom business logic and routes
- 💾 **Multiple Database Support** – SQLite and PostgreSQL adapters, with migration scripts included
- 🛡️ **Security First** – CSRF protection, secure cookies, rate limiting, and input validation
- ⚡ **Rate Limiting** – Configurable, per-endpoint rate limiting with memory or database storage
- 🔁 **Token Refresh Flow** – Automatic token refresh and session extension
- 📦 **Minimal Dependencies** – Standard library first, production-ready, and framework-agnostic
- 🧩 **Comprehensive Configuration** – Flexible, type-safe config with sensible defaults and environment variable support
- 🧪 **Test Coverage** – Unit, integration, and E2E tests reflecting production scenarios

---

## 🚀 Quick Start

### Installation

```bash
go get github.com/GoBetterAuth/go-better-auth
```

### Basic Usage

Use go-better-auth as a complete authentication framework with built-in HTTP handlers:

```go
package main

import (
    "log"
    "net/http"

    gobetterauth "github.com/GoBetterAuth/go-better-auth"
    "github.com/GoBetterAuth/go-better-auth/domain"
)

func main() {
    auth, err := gobetterauth.New(&domain.Config{
        BaseURL: "http://localhost:8080",

        Database: domain.DatabaseConfig{
            Provider:          "sqlite",
            ConnectionString: ":memory:",
        },

        EmailAndPassword: &domain.EmailPasswordConfig{
            Enabled:    true,
            AutoSignIn: true,
        },
    })

    if err != nil {
        log.Fatal(err)
    }

    // Mount built-in HTTP handlers for all auth endpoints
    http.Handle("/api/auth/", auth.Handler())

    log.Println("Server running on http://localhost:8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

For comprehensive configuration examples, see [EXAMPLES.md](./EXAMPLES.md).

### Detailed Setup and Initialization

Go Better Auth is initialized via the `gobetterauth.New(config)` function, which takes a `domain.Config` struct. The library provides built-in HTTP handlers that implement all authentication endpoints.

**Architecture Overview:**

```
┌─────────────────────────┐
│ Your Application        │
│ (any HTTP server)       │
└────────────┬────────────┘
             │ mounts
             │
       ┌─────▼──────────┐
       │ auth.Handler() │
       │ (http.Handler) │
       └─────┬──────────┘
             │
       ┌─────▼──────────┐
       │ Domain Layer   │
       │ Repositories   │
       │ Use Cases      │
       │ Services       │
       └─────┬──────────┘
             │
       ┌─────▼────────────┐
       │ Database Adapters│
       │ (PostgreSQL, etc)│
       └──────────────────┘
```

---

**Setup Steps:**

1. **Configuration**: Populate the `domain.Config` struct with your settings. Required: `Database.Provider` and `Database.ConnectionString`
2. **Database Setup**: Run migrations from `migrations/` folder
3. **Email Integration**: Provide callbacks for email sending (optional)
4. **Session Configuration**: Customize expiration and behavior (optional, defaults applied)
5. **OAuth Setup**: Configure provider credentials and redirect URLs (optional)
6. **Initialization**: Call `gobetterauth.New(config)`
7. **Mount Handler**: Use `auth.Handler()` to get built-in handlers and mount on your HTTP server
8. **Deploy**: The library is thread-safe and production-ready

---

## ⚙️ Configuration

Go Better Auth provides a flexible, comprehensive configuration system. Configuration is done via the `domain.Config` struct with sensible defaults applied automatically.

### Core Configuration

#### AppName

Application name for identification:

```go
AppName: "My Application"
```

#### BaseURL

Base URL for your application. Auto-detects from `GO_BETTER_AUTH_URL` environment variable:

```go
BaseURL: "https://example.com"
```

#### BasePath

Base path for auth routes (default: `/api/auth`):

```go
BasePath: "/api/auth"
```

#### TrustedOrigins

Configure CORS trusted origins with static origins, dynamic functions, and wildcard support:

```go
TrustedOrigins: domain.TrustedOriginsConfig{
    StaticOrigins: []string{
        "https://example.com",
        "https://*.example.com",  // Wildcard subdomain support
        "http://localhost:3000",  // Development
    },
    DynamicOrigins: func(r *http.Request) []string {
        // Dynamic origin validation based on request
        return []string{"https://dynamic.example.com"}
    },
}
```

#### Secret

Secret key for encryption, signing, and hashing. Auto-detects from `GO_BETTER_AUTH_SECRET` or `AUTH_SECRET` environment variables. **Required in production**:

```go
Secret: "your-secret-key-here"
```

### Database Configuration

#### DatabaseConfig

Configure database connection and settings:

```go
Database: domain.DatabaseConfig{
    Provider:          "postgres",  // "sqlite" or "postgres"
    ConnectionString: "postgres://user:pass@localhost/dbname?sslmode=disable",
    DB:               nil,  // Optional custom *sql.DB instance
    Casing:           "snake",  // "camel" or "snake" for column naming
}
```

### Authentication Methods

#### EmailAndPassword

Enable email and password authentication:

```go
EmailAndPassword: &domain.EmailPasswordConfig{
    Enabled:                  true,
    DisableSignUp:            false,
    RequireEmailVerification: true,
    MinPasswordLength:        8,
    MaxPasswordLength:        128,
    AutoSignIn:               true,

    SendResetPassword: func(ctx context.Context, user *domain.User, url string, token string) error {
        // Implement email sending logic
        return nil
    },

    ResetPasswordTokenExpiresIn: 3600,  // 1 hour

    Password: &domain.PasswordConfig{  // Optional custom password hashing
        Hash: func(password string) (string, error) {
            // Custom hash implementation
            return password, nil
        },
        Verify: func(password, hash string) bool {
            // Custom verification implementation
            return password == hash
        },
    },
}
```

#### EmailVerification

Configure email verification workflow:

```go
EmailVerification: &domain.EmailVerificationConfig{
    SendVerificationEmail: func(ctx context.Context, user *domain.User, url string, token string) error {
        // Implement email sending logic
        return nil
    },

    SendOnSignUp:                true,
    SendOnSignIn:                false,
    AutoSignInAfterVerification: true,
    ExpiresIn:                   3600,  // 1 hour
}
```

#### SocialProviders

Configure OAuth providers:

```go
SocialProviders: &domain.SocialProvidersConfig{
    Google: &domain.GoogleProviderConfig{
        ClientID:     "google-client-id",
        ClientSecret: "google-client-secret",
        RedirectURI:  "https://example.com/api/auth/callback/google",
    },

    GitHub: &domain.GitHubProviderConfig{
        ClientID:     "github-client-id",
        ClientSecret: "github-client-secret",
        RedirectURI:  "https://example.com/api/auth/callback/github",
    },

    Discord: &domain.DiscordProviderConfig{
        ClientID:     "discord-client-id",
        ClientSecret: "discord-client-secret",
        RedirectURI:  "https://example.com/api/auth/callback/discord",
    },

    Generic: map[string]*domain.GenericOAuthConfig{
        "custom": {
            ClientID:       "custom-client-id",
            ClientSecret:   "custom-client-secret",
            RedirectURI:    "https://example.com/api/auth/callback/custom",
            AuthURL:        "https://custom.com/oauth/authorize",
            TokenURL:       "https://custom.com/oauth/token",
            UserInfoURL:    "https://custom.com/oauth/userinfo",
            Scopes:         []string{"openid", "profile", "email"},
            UserInfoMapper: func(data map[string]any) *domain.OAuthUserInfo {
                return &domain.OAuthUserInfo{
                    ID:    data["sub"].(string),
                    Email: data["email"].(string),
                    Name:  data["name"].(string),
                }
            },
        },
    },
}
```

### Session Management

#### Session

Customize session behavior:

```go
Session: &domain.SessionConfig{
    ModelName:             "session",
    Fields: map[string]string{
        "userId": "user_id",  // Custom field mapping
    },
    ExpiresIn:             604800,  // 7 days
    UpdateAge:             86400,   // 1 day
    DisableSessionRefresh: false,

    AdditionalFields: map[string]domain.AdditionalField{
        "device": {Type: "string"},
    },

    StoreSessionInDatabase:    true,
    PreserveSessionInDatabase: false,

    CookieCache: &domain.CookieCacheConfig{
        Enabled: true,
        MaxAge:  300,  // 5 minutes
    },
}
```

### User Management

#### User

Configure user model customization:

```go
User: &domain.UserConfig{
    ModelName: "user",
    Fields: map[string]string{
        "email": "email_address",  // Custom field mapping
    },

    AdditionalFields: map[string]domain.AdditionalField{
        "phone": {Type: "string"},
    },

    ChangeEmail: &domain.ChangeEmailConfig{
        Enabled: true,
        SendChangeEmailVerification: func(ctx context.Context, user *domain.User, newEmail string, url string, token string) error {
            // Implement email sending logic
            return nil
        },
    },

    DeleteUser: &domain.DeleteUserConfig{
        Enabled: true,
        SendDeleteAccountVerification: func(ctx context.Context, user *domain.User, url string, token string) error {
            // Implement email sending logic
            return nil
        },
        BeforeDelete: func(ctx context.Context, user *domain.User) error {
            // Pre-deletion logic
            return nil
        },
        AfterDelete: func(ctx context.Context, user *domain.User) error {
            // Post-deletion logic
            return nil
        },
    },
}
```

### Account Management

#### Account

Configure account linking and OAuth settings:

```go
Account: &domain.AccountConfig{
    ModelName: "account",
    Fields: map[string]string{
        "userId": "user_id",
    },

    EncryptOAuthTokens:   true,
    UpdateAccountOnSignIn: true,

    AccountLinking: &domain.AccountLinkingConfig{
        Enabled:             true,
        TrustedProviders:    []string{"google", "github"},
        AllowDifferentEmails: false,
        AllowUnlinkingAll:    false,
    },
}
```

### Verification Management

#### Verification

Configure verification token storage:

```go
Verification: &domain.VerificationConfig{
    ModelName: "verification",
    Fields: map[string]string{
        "token": "verification_token",
    },
    DisableCleanup: false,
}
```

### Rate Limiting

#### RateLimit

Configure rate limiting to prevent abuse:

```go
RateLimit: &domain.RateLimitOptions{
    Enabled:   true,
    Window:    10,   // 10 seconds
    Max:       100,  // 100 requests per window
    Algorithm: "fixed-window", // "fixed-window" or "sliding-window"
    Storage:   "memory",  // "memory", "database", or "secondary-storage"

    CustomRules: map[string]domain.RateLimitRule{
        "/api/auth/sign-in": {
            Window: 300,  // 5 minutes
            Max:    5,    // 5 attempts
        },
        "/api/auth/sign-up": {
            Window: 3600, // 1 hour
            Max:    3,    // 3 attempts
        },
    },

    ModelName: "rateLimit",
}
```

**Rate Limiting Algorithms:**

- **Fixed Window**: Simple counter that resets at window boundaries. Fast and memory-efficient, but can allow bursts of traffic at window boundaries (e.g., 100 requests at 9:59, another 100 at 10:00).

- **Sliding Window**: Uses weighted counts from current and previous windows for smoother rate limiting. Prevents boundary bursts by gradually transitioning between windows. Slightly more computation but provides better distribution of requests over time.

Example with sliding window:

```go
RateLimit: &domain.RateLimitOptions{
    Enabled:   true,
    Algorithm: "sliding-window",
    Window:    60,  // 1 minute
    Max:       100, // 100 requests per minute (smoothly distributed)
}
```

### Advanced Configuration

#### Advanced

Configure advanced security and cookie settings:

```go
Advanced: &domain.AdvancedConfig{
    IPAddress: &domain.IPAddressConfig{
        IPAddressHeaders:  []string{"X-Forwarded-For", "X-Real-IP"},
        DisableIpTracking: false,
    },

    UseSecureCookies: true,

    DisableCSRFCheck: false,  // ⚠️ Security risk if enabled

    CrossSubDomainCookies: &domain.CrossSubDomainCookiesConfig{
        Enabled: true,
        AdditionalCookies: []string{"customCookie"},
        Domain:  ".example.com",
    },

    Cookies: map[string]domain.CookieConfig{
        "session": {
            Name: "custom_session",
            Attributes: domain.CookieAttributes{
                HTTPOnly: true,
                Secure:   true,
                SameSite: "Lax",
                Path:     "/",
                Domain:   ".example.com",
                MaxAge:   604800,
            },
        },
    },

    DefaultCookieAttributes: &domain.CookieAttributes{
        HTTPOnly: true,
        Secure:   true,
        SameSite: "Lax",
        Path:     "/",
        MaxAge:   604800,
    },

    CookiePrefix: "gba",

    Database: &domain.DatabaseAdvancedConfig{
        UseNumberId:           false,
        GenerateId:            nil,  // Custom ID generator function
        DefaultFindManyLimit:  100,
    },
}
```

### Logging Configuration

#### Logger

Configure logging behavior:

```go
Logger: &domain.LoggerConfig{
    Disabled:     false,
    DisableColors: false,
    Level:        domain.LogLevelInfo,  // "debug", "info", "warn", "error"

    Log: func(level domain.LogLevel, message string, args ...interface{}) {
        // Custom logging implementation
    },
}
```

### Database Hooks

#### DatabaseHooks

Add lifecycle hooks for database operations:

```go
DatabaseHooks: &domain.DatabaseHooksConfig{
    User: &domain.ModelHooks{
        Create: &domain.CRUDHooks{
            Before: func(ctx context.Context, data interface{}) (interface{}, error) {
                // Pre-create logic
                return data, nil
            },
            After: func(ctx context.Context, result interface{}) error {
                // Post-create logic
                return nil
            },
        },
        Update: &domain.CRUDHooks{
            Before: func(ctx context.Context, data interface{}) (interface{}, error) {
                // Pre-update logic
                return data, nil
            },
            After: func(ctx context.Context, result interface{}) error {
                // Post-update logic
                return nil
            },
        },
    },
    // Similar hooks available for Session, Account, Verification
}
```

### API Error Handling

#### OnAPIError

Configure custom error handling:

```go
OnAPIError: &domain.OnAPIErrorConfig{
    Throw:    false,
    OnError: func(err error, ctx context.Context) {
        // Custom error handling logic
    },
    ErrorURL: "/api/auth/error",
}
```

### Request Lifecycle Hooks

#### Hooks

Add request lifecycle hooks:

```go
Hooks: &domain.HooksConfig{
    Before: func(ctx *domain.RequestContext) (*domain.HookResponse, error) {
        // Pre-request logic
        // ctx contains: Path, Method, Body, Headers, Query, Request, Context

        // Optionally return modified context
        if ctx.Path == "/auth/sign-up" {
            return &domain.HookResponse{
                Context: &domain.RequestContext{
                    Body: map[string]any{
                        "name": "Custom Name",
                    },
                },
            }, nil
        }

        // Return error to block the request (403 Forbidden)
        // return nil, errors.New("request blocked")

        return nil, nil
    },
    After: func(ctx *domain.RequestContext) (*domain.HookResponse, error) {
        // Post-request logic (errors are silently handled)
        return nil, nil
    },
}
```

#### RequestContext Object

The `RequestContext` object passed to hooks provides:

- **Path** (string): The URL path of the request (e.g., "/auth/signin")
- **Method** (string): The HTTP method (GET, POST, etc.)
- **Body** (any): The parsed request body (for POST/PUT/PATCH requests)
- **Headers** (map[string][]string): Request headers
- **Query** (map[string][]string): URL query parameters
- **Request** (\*http.Request): The underlying HTTP request object
- **Context** (map[string]any): Generic key-value store for auth-related data

#### Hook Examples

**Example 1: Modify Request Context Before Processing**

```go
Before: func(ctx *domain.RequestContext) (*domain.HookResponse, error) {
    if ctx.Path == "/auth/sign-up" {
        // Modify context for downstream processing
        return &domain.HookResponse{
            Context: &domain.RequestContext{
                Body: map[string]any{
                    "company": "Default Corp",
                },
                Context: map[string]any{
                    "isSignUp": true,
                    "source":   "web",
                },
            },
        }, nil
    }
    return nil, nil
},
```

**Example 2: Block Requests Based on Headers**

```go
Before: func(ctx *domain.RequestContext) (*domain.HookResponse, error) {
    // Access headers to make authorization decisions
    authHeader, exists := ctx.Headers["Authorization"]
    if !exists || len(authHeader) == 0 {
        return nil, errors.New("missing authorization header")
    }
    return nil, nil
},
```

**Example 3: Access Query Parameters**

```go
Before: func(ctx *domain.RequestContext) (*domain.HookResponse, error) {
    // Access query parameters
    if emails, ok := ctx.Query["email"]; ok && len(emails) > 0 {
        email := emails[0]
        // Process email
        return &domain.HookResponse{
            Context: &domain.RequestContext{
                Context: map[string]any{
                    "providedEmail": email,
                },
            },
        }, nil
    }
    return nil, nil
},
```

**Example 4: Post-Request Logging**

```go
After: func(ctx *domain.RequestContext) (*domain.HookResponse, error) {
    // Log after request processing
    log.Printf("Request completed: %s %s, Context: %v",
        ctx.Method, ctx.Path, ctx.Context)
    return nil, nil
},
```

### Plugins

#### Plugins

Extend functionality with plugins:

```go
Plugins: []domain.Plugin{
    &MyCustomPlugin{},
}
```

### Environment Variables

Go Better Auth automatically reads from environment variables:

- `GO_BETTER_AUTH_URL` - Base URL (overridden by `BaseURL` config)
- `GO_BETTER_AUTH_SECRET` or `AUTH_SECRET` - Secret key (required in production)
- `DATABASE_URL` - Database connection string

### Default Values

Sensible defaults are applied:

- **BaseURL**: `http://localhost:8080`
- **BasePath**: `/api/auth`
- **Session.ExpiresIn**: 604800 seconds (7 days)
- **Session.UpdateAge**: 86400 seconds (1 day)
- **EmailVerification.ExpiresIn**: 3600 seconds (1 hour)
- **EmailAndPassword.MinPasswordLength**: 8
- **EmailAndPassword.MaxPasswordLength**: 128
- **RateLimit.Window**: 10 seconds
- **RateLimit.Max**: 100 requests
- **Database.Casing**: `snake`

---

## ⚡ Rate Limiting

Go Better Auth includes built-in rate limiting for authentication endpoints when enabled in configuration.

### Storage Options

Rate limiting supports multiple storage backends:

- **"memory"**: In-memory storage (default, single instance only)
- **"database"**: Database-backed storage (recommended for production)
- **"secondary-storage"**: Custom storage implementation

### Setup

```go
RateLimit: &domain.RateLimitOptions{
    Enabled: true,
    Window:  60,   // 60 seconds
    Max:     100,  // 100 requests per window
    Storage: "database",

    CustomRules: map[string]domain.RateLimitRule{
        "/api/auth/sign-in": {Window: 300, Max: 5},
    },
}
```

The built-in handlers will automatically apply rate limiting to prevent abuse. Exceeded rate limits return HTTP 429 (Too Many Requests).

---

## 🔐 Multi-Factor Authentication (MFA)

TOTP-based MFA is available as a separate package. See the `mfa/` directory for implementation details.

---

## 🎫 JWT Token Management

JWT support with RS256 signing is available as a separate package. See the `jwt/` directory for implementation details.

### Setup

```go
import "github.com/GoBetterAuth/go-better-auth/jwt"

// Create JWT manager with auto-generated RSA keys
jwtManager, err := jwt.NewManager("https://example.com", []string{"https://example.com"})

// Or load from existing keys
jwtManager, err := jwt.NewManagerWithKeys(privateKey, publicKey, "https://example.com", []string{"https://example.com"})
```

### Usage

```go
// Create access and refresh token pair
tokenPair, err := jwtManager.CreateTokenPair(userID, email, name, accessExpiry, refreshExpiry)

// Verify token
claims, err := jwtManager.VerifyToken(tokenString)

// Refresh access token
newAccessToken, err := jwtManager.RefreshAccessToken(refreshToken, newExpiry)
```

---

## 🏗️ Architecture

Go Better Auth follows **Clean Architecture** principles with built-in HTTP handlers:

```
┌────────────────────────────────────────────────────┐
│          Go Better Auth Library                    │
├────────────────────────────────────────────────────┤
│  Standalone HTTP Handlers                          │
│  • Built-in http.Handler implementation            │
│  • auth.Handler() returns ready-to-use handler     │
│  • Mount on any standard HTTP server               │
├────────────────────────────────────────────────────┤
│  Core Components                                   │
│  • Domain Models (User, Session, Account, etc.)    │
│  • Use Cases (business logic)                      │
│  • Repositories (data persistence interfaces)      │
│  • Services (CSRF, Rate Limiting, etc.)            │
├────────────────────────────────────────────────────┤
│  Database Adapters                                 │
│  • PostgreSQL • SQLite • Extensible                │
└────────────────────────────────────────────────────┘
```

**Key Design Principles:**

1. **Framework-Agnostic Core**: Clean separation between business logic and HTTP concerns
2. **Standard Library First**: Handlers implement `net/http.Handler` interface
3. **Clean Separation**: Business logic separate from HTTP delivery
4. **Extensible**: Database adapters, plugins, and services
5. **Production-Ready**: Thread-safe, secure, and performant

---

## 🔌 Plugin System

Create custom plugins to extend the library with additional business logic:

```go
package main

import (
    "context"
    "net/http"

    "github.com/GoBetterAuth/go-better-auth/plugin"
)

type CustomPlugin struct {
    plugin.BasePlugin
}

func NewCustomPlugin() *CustomPlugin {
    return &CustomPlugin{
        BasePlugin: plugin.BasePlugin{Name: "custom"},
    }
}

func (p *CustomPlugin) Name() string {
    return p.BasePlugin.Name
}

func (p *CustomPlugin) Initialize(config *plugin.PluginConfig) error {
    // Initialize plugin
    return nil
}

func (p *CustomPlugin) RegisterRoutes(router plugin.Router) {
    // Register custom routes
    router.Get("/custom", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Custom route"))
    })
}

func (p *CustomPlugin) RegisterMiddleware() []plugin.Middleware {
    // Register middleware
    return []plugin.Middleware{}
}
```

Plugins are instantiated and passed to the Go Better Auth config during initialization.

---

## 💾 Database Adapters

### SQLite

```go
Database: domain.DatabaseConfig{
    Provider:         "sqlite",
    ConnectionString: "/path/to/database.db", // or ":memory:" for in-memory
}
```

### PostgreSQL

```go
Database: domain.DatabaseConfig{
    Provider:         "postgres",
    ConnectionString: "postgres://user:password@localhost/dbname?sslmode=disable",
}
```

**Schema Migration:**

Database schemas are provided in the `migrations/` folder.

---

### CSRF Protection

Automatic CSRF token validation for state-changing operations. Can be disabled via `Advanced.DisableCSRFCheck` (not recommended for production).

---

## 🌟 Examples

See the `examples/` directory for complete examples:

- Basic email/password authentication
- OAuth integration
- Custom plugin development
- Multi-provider setup

For comprehensive configuration examples, see [EXAMPLES.md](./EXAMPLES.md).

---

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. Follow Go best practices and conventions
2. Maintain clean architecture principles
3. Add tests for new features
4. Update documentation

---

## 📄 License

Apache 2.0 License - see LICENSE file for details

---

## 📞 Support

- GitHub Issues: [Report bugs or request features](https://github.com/GoBetterAuth/go-better-auth/issues)
- Documentation: [Full documentation](https://github.com/GoBetterAuth/go-better-auth/wiki)

## Extra notes:

This project was inspired by [Better Auth](https://better-auth.com) but it is not a direct port of it. In the near future the API may change and we have our own roadmap and plans to implement many new features.

---
