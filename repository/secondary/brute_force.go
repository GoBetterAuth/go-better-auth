package secondary

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/GoBetterAuth/go-better-auth/domain/security"
	"github.com/GoBetterAuth/go-better-auth/storage"
)

const (
	bruteForceAttemptPrefix = "brute_force_attempt:"
	accountLockoutPrefix    = "account_lockout:"
	ipAttemptPrefix         = "ip_attempt:"
)

// SecondaryStorageBruteForceRepository implements security.BruteForceRepository using secondary storage
type SecondaryStorageBruteForceRepository struct {
	storage storage.SecondaryStorage
	mu      sync.Mutex // Protects concurrent access to attempt recording
}

// NewSecondaryStorageBruteForceRepository creates a new brute force repository using secondary storage
func NewSecondaryStorageBruteForceRepository(storage storage.SecondaryStorage) *SecondaryStorageBruteForceRepository {
	return &SecondaryStorageBruteForceRepository{
		storage: storage,
	}
}

// RecordAttempt records a failed login attempt for an email
func (r *SecondaryStorageBruteForceRepository) RecordAttempt(email, ipAddress string) error {
	// Use mutex to ensure atomic read-modify-write operations
	r.mu.Lock()
	defer r.mu.Unlock()

	ctx := context.Background()

	// Record email attempt
	emailKey := fmt.Sprintf("%s%s", bruteForceAttemptPrefix, email)
	attempts, err := r.getAttempts(ctx, emailKey)
	if err != nil {
		return fmt.Errorf("failed to get attempts: %w", err)
	}

	attempt := &security.BruteForceAttempt{
		Email:     email,
		IPAddress: ipAddress,
		Timestamp: time.Now(),
	}
	attempts = append(attempts, attempt)

	if err := r.setAttempts(ctx, emailKey, attempts); err != nil {
		return fmt.Errorf("failed to set attempts: %w", err)
	}

	// Record IP attempt if IP rate limiting is enabled
	if ipAddress != "" {
		ipKey := fmt.Sprintf("%s%s", ipAttemptPrefix, ipAddress)
		ipAttempts, err := r.getAttempts(ctx, ipKey)
		if err != nil {
			return fmt.Errorf("failed to get IP attempts: %w", err)
		}

		ipAttempts = append(ipAttempts, attempt)

		if err := r.setAttempts(ctx, ipKey, ipAttempts); err != nil {
			return fmt.Errorf("failed to set IP attempts: %w", err)
		}
	}

	return nil
}

// GetAttemptCount returns the number of failed attempts in the last duration for an email
func (r *SecondaryStorageBruteForceRepository) GetAttemptCount(email string, duration time.Duration) (int, error) {
	ctx := context.Background()
	key := fmt.Sprintf("%s%s", bruteForceAttemptPrefix, email)
	attempts, err := r.getAttempts(ctx, key)
	if err != nil {
		return 0, fmt.Errorf("failed to get attempts: %w", err)
	}

	cutoffTime := time.Now().Add(-duration)
	count := 0
	for _, attempt := range attempts {
		if attempt.Timestamp.After(cutoffTime) {
			count++
		}
	}

	return count, nil
}

// GetAttemptCountByIP returns the number of failed attempts in the last duration for an IP
func (r *SecondaryStorageBruteForceRepository) GetAttemptCountByIP(ipAddress string, duration time.Duration) (int, error) {
	ctx := context.Background()
	key := fmt.Sprintf("%s%s", ipAttemptPrefix, ipAddress)
	attempts, err := r.getAttempts(ctx, key)
	if err != nil {
		return 0, fmt.Errorf("failed to get IP attempts: %w", err)
	}

	cutoffTime := time.Now().Add(-duration)
	count := 0
	for _, attempt := range attempts {
		if attempt.Timestamp.After(cutoffTime) {
			count++
		}
	}

	return count, nil
}

// LockAccount locks an account until the specified time
func (r *SecondaryStorageBruteForceRepository) LockAccount(email string, unlocksAt time.Time) error {
	ctx := context.Background()
	key := fmt.Sprintf("%s%s", accountLockoutPrefix, email)
	lockout := &security.AccountLockout{
		Email:     email,
		LockedAt:  time.Now(),
		UnlocksAt: unlocksAt,
	}

	data, err := json.Marshal(lockout)
	if err != nil {
		return fmt.Errorf("failed to marshal lockout: %w", err)
	}

	if err := r.storage.Set(ctx, key, string(data), 0); err != nil {
		return fmt.Errorf("failed to set lockout: %w", err)
	}

	return nil
}

// UnlockAccount unlocks a locked account
func (r *SecondaryStorageBruteForceRepository) UnlockAccount(email string) error {
	ctx := context.Background()
	key := fmt.Sprintf("%s%s", accountLockoutPrefix, email)
	if err := r.storage.Delete(ctx, key); err != nil {
		if strings.Contains(err.Error(), "key not found") {
			return nil // Already unlocked
		}
		return fmt.Errorf("failed to delete lockout: %w", err)
	}
	return nil
}

// IsAccountLocked checks if an account is currently locked
func (r *SecondaryStorageBruteForceRepository) IsAccountLocked(email string) (bool, error) {
	lockout, err := r.GetLockoutInfo(email)
	if err != nil {
		return false, err
	}
	if lockout == nil {
		return false, nil
	}
	return time.Now().Before(lockout.UnlocksAt), nil
}

// GetLockoutInfo returns lockout information for an email
func (r *SecondaryStorageBruteForceRepository) GetLockoutInfo(email string) (*security.AccountLockout, error) {
	ctx := context.Background()
	key := fmt.Sprintf("%s%s", accountLockoutPrefix, email)
	data, err := r.storage.Get(ctx, key)
	if err != nil {
		if strings.Contains(err.Error(), "key not found") {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get lockout: %w", err)
	}

	dataStr, ok := data.(string)
	if !ok {
		return nil, fmt.Errorf("invalid data type for lockout")
	}

	var lockout security.AccountLockout
	if err := json.Unmarshal([]byte(dataStr), &lockout); err != nil {
		return nil, fmt.Errorf("failed to unmarshal lockout: %w", err)
	}

	return &lockout, nil
}

// ClearAttempts clears all failed attempts for an email
func (r *SecondaryStorageBruteForceRepository) ClearAttempts(email string) error {
	ctx := context.Background()
	key := fmt.Sprintf("%s%s", bruteForceAttemptPrefix, email)
	if err := r.storage.Delete(ctx, key); err != nil {
		if strings.Contains(err.Error(), "key not found") {
			return nil // Already cleared
		}
		return fmt.Errorf("failed to delete attempts: %w", err)
	}
	return nil
}

// getAttempts retrieves attempts from storage
func (r *SecondaryStorageBruteForceRepository) getAttempts(ctx context.Context, key string) ([]*security.BruteForceAttempt, error) {
	data, err := r.storage.Get(ctx, key)
	if err != nil {
		if strings.Contains(err.Error(), "key not found") {
			return []*security.BruteForceAttempt{}, nil
		}
		return nil, err
	}

	dataStr, ok := data.(string)
	if !ok {
		return nil, fmt.Errorf("invalid data type for attempts")
	}

	var attempts []*security.BruteForceAttempt
	if err := json.Unmarshal([]byte(dataStr), &attempts); err != nil {
		return nil, fmt.Errorf("failed to unmarshal attempts: %w", err)
	}

	return attempts, nil
}

// setAttempts stores attempts in storage
func (r *SecondaryStorageBruteForceRepository) setAttempts(ctx context.Context, key string, attempts []*security.BruteForceAttempt) error {
	data, err := json.Marshal(attempts)
	if err != nil {
		return fmt.Errorf("failed to marshal attempts: %w", err)
	}

	if err := r.storage.Set(ctx, key, string(data), 0); err != nil {
		return fmt.Errorf("failed to set attempts: %w", err)
	}

	return nil
}
