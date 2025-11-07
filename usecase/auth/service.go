package auth

import (
	"github.com/GoBetterAuth/go-better-auth/domain"
	"github.com/GoBetterAuth/go-better-auth/domain/account"
	"github.com/GoBetterAuth/go-better-auth/domain/session"
	"github.com/GoBetterAuth/go-better-auth/domain/user"
	"github.com/GoBetterAuth/go-better-auth/domain/verification"
	"github.com/GoBetterAuth/go-better-auth/usecase/security_protection"
	"github.com/GoBetterAuth/go-better-auth/vault"
)

// PasswordHasher provides password hashing and verification functionality
type PasswordHasher interface {
	Hash(password string) (string, error)
	Verify(password, hash string) (bool, error)
}

// DefaultPasswordHasher implements PasswordHasher using the default crypto functions
type DefaultPasswordHasher struct{}

func (h *DefaultPasswordHasher) Hash(password string) (string, error) {
	return vault.HashPassword(password)
}

func (h *DefaultPasswordHasher) Verify(password, hash string) (bool, error) {
	return vault.VerifyPassword(password, hash)
}

// CustomPasswordHasher implements PasswordHasher using custom functions from config
type CustomPasswordHasher struct {
	hashFunc   func(password string) (string, error)
	verifyFunc func(password, hash string) bool
}

func (h *CustomPasswordHasher) Hash(password string) (string, error) {
	return h.hashFunc(password)
}

func (h *CustomPasswordHasher) Verify(password, hash string) (bool, error) {
	return h.verifyFunc(password, hash), nil
}

// Service provides authentication use cases
type Service struct {
	config            *domain.Config
	userRepo          user.Repository
	sessionRepo       session.Repository
	accountRepo       account.Repository
	verificationRepo  verification.Repository
	passwordHasher    PasswordHasher
	bruteForceService *security_protection.BruteForceService
}

// NewService creates a new authentication service
func NewService(
	config *domain.Config,
	userRepo user.Repository,
	sessionRepo session.Repository,
	accountRepo account.Repository,
	verificationRepo verification.Repository,
) *Service {
	var passwordHasher PasswordHasher

	// Use custom password hasher if configured, otherwise use default
	if config.EmailAndPassword != nil && config.EmailAndPassword.Password != nil {
		if config.EmailAndPassword.Password.Hash != nil && config.EmailAndPassword.Password.Verify != nil {
			passwordHasher = &CustomPasswordHasher{
				hashFunc:   config.EmailAndPassword.Password.Hash,
				verifyFunc: config.EmailAndPassword.Password.Verify,
			}
		}
	}

	if passwordHasher == nil {
		passwordHasher = &DefaultPasswordHasher{}
	}

	return &Service{
		config:           config,
		userRepo:         userRepo,
		sessionRepo:      sessionRepo,
		accountRepo:      accountRepo,
		verificationRepo: verificationRepo,
		passwordHasher:   passwordHasher,
	}
}

// SetBruteForceService sets the brute force service for the authentication service
func (s *Service) SetBruteForceService(service *security_protection.BruteForceService) {
	s.bruteForceService = service
}

// GetConfig returns the configuration
func (s *Service) GetConfig() *domain.Config {
	return s.config
}
