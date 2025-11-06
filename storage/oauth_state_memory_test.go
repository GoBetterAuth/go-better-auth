package storage

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestInMemoryOAuthStateStorage_Store(t *testing.T) {
	storage := NewInMemoryOAuthStateStorage(100 * time.Millisecond)
	defer storage.Close()

	ctx := context.Background()
	stateID := "test-state-123"
	state := &OAuthState{
		State:      stateID,
		ProviderID: "google",
		RedirectTo: "https://example.com/callback",
		UserID:     "user123",
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(10 * time.Minute),
	}

	err := storage.Store(ctx, stateID, state, 10*time.Minute)
	if err != nil {
		t.Fatalf("failed to store state: %v", err)
	}
}

func TestInMemoryOAuthStateStorage_StoreEmptyStateID(t *testing.T) {
	storage := NewInMemoryOAuthStateStorage(100 * time.Millisecond)
	defer storage.Close()

	ctx := context.Background()
	state := &OAuthState{
		State:      "test-state",
		ProviderID: "google",
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(10 * time.Minute),
	}

	err := storage.Store(ctx, "", state, 10*time.Minute)
	if err == nil {
		t.Error("expected error for empty stateID")
	}
}

func TestInMemoryOAuthStateStorage_StoreNilState(t *testing.T) {
	storage := NewInMemoryOAuthStateStorage(100 * time.Millisecond)
	defer storage.Close()

	ctx := context.Background()

	err := storage.Store(ctx, "test-state", nil, 10*time.Minute)
	if err == nil {
		t.Error("expected error for nil state")
	}
}

func TestInMemoryOAuthStateStorage_Retrieve(t *testing.T) {
	storage := NewInMemoryOAuthStateStorage(100 * time.Millisecond)
	defer storage.Close()

	ctx := context.Background()
	stateID := "test-state-123"
	originalState := &OAuthState{
		State:      stateID,
		ProviderID: "google",
		RedirectTo: "https://example.com/callback",
		UserID:     "user123",
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(10 * time.Minute),
	}

	// Store the state
	err := storage.Store(ctx, stateID, originalState, 10*time.Minute)
	if err != nil {
		t.Fatalf("failed to store state: %v", err)
	}

	// Retrieve the state
	retrievedState, err := storage.Retrieve(ctx, stateID)
	if err != nil {
		t.Fatalf("failed to retrieve state: %v", err)
	}

	// Verify the retrieved state
	if retrievedState.State != originalState.State {
		t.Errorf("expected state %s, got %s", originalState.State, retrievedState.State)
	}
	if retrievedState.ProviderID != originalState.ProviderID {
		t.Errorf("expected provider %s, got %s", originalState.ProviderID, retrievedState.ProviderID)
	}
	if retrievedState.RedirectTo != originalState.RedirectTo {
		t.Errorf("expected redirect %s, got %s", originalState.RedirectTo, retrievedState.RedirectTo)
	}
	if retrievedState.UserID != originalState.UserID {
		t.Errorf("expected user ID %s, got %s", originalState.UserID, retrievedState.UserID)
	}
}

func TestInMemoryOAuthStateStorage_RetrieveNonExistent(t *testing.T) {
	storage := NewInMemoryOAuthStateStorage(100 * time.Millisecond)
	defer storage.Close()

	ctx := context.Background()

	_, err := storage.Retrieve(ctx, "non-existent-state")
	if err == nil {
		t.Error("expected error for non-existent state")
	}
}

func TestInMemoryOAuthStateStorage_RetrieveExpired(t *testing.T) {
	storage := NewInMemoryOAuthStateStorage(100 * time.Millisecond)
	defer storage.Close()

	ctx := context.Background()
	stateID := "expired-state-123"
	expiredState := &OAuthState{
		State:      stateID,
		ProviderID: "google",
		CreatedAt:  time.Now().Add(-20 * time.Minute),
		ExpiresAt:  time.Now().Add(-10 * time.Minute), // Already expired
	}

	// Store the expired state
	err := storage.Store(ctx, stateID, expiredState, -10*time.Minute) // Negative TTL
	if err != nil {
		t.Fatalf("failed to store expired state: %v", err)
	}

	// Try to retrieve - should fail
	_, err = storage.Retrieve(ctx, stateID)
	if err == nil {
		t.Error("expected error for expired state")
	}
}

func TestInMemoryOAuthStateStorage_Delete(t *testing.T) {
	storage := NewInMemoryOAuthStateStorage(100 * time.Millisecond)
	defer storage.Close()

	ctx := context.Background()
	stateID := "test-state-123"
	state := &OAuthState{
		State:      stateID,
		ProviderID: "google",
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(10 * time.Minute),
	}

	// Store the state
	err := storage.Store(ctx, stateID, state, 10*time.Minute)
	if err != nil {
		t.Fatalf("failed to store state: %v", err)
	}

	// Verify it exists
	_, err = storage.Retrieve(ctx, stateID)
	if err != nil {
		t.Fatalf("state should exist before deletion: %v", err)
	}

	// Delete the state
	err = storage.Delete(ctx, stateID)
	if err != nil {
		t.Fatalf("failed to delete state: %v", err)
	}

	// Verify it's gone
	_, err = storage.Retrieve(ctx, stateID)
	if err == nil {
		t.Error("state should not exist after deletion")
	}
}

func TestInMemoryOAuthStateStorage_CleanupExpired(t *testing.T) {
	storage := NewInMemoryOAuthStateStorage(100 * time.Millisecond)
	defer storage.Close()

	ctx := context.Background()

	// Add some expired states
	for i := 0; i < 3; i++ {
		stateID := fmt.Sprintf("expired-state-%d", i)
		expiredState := &OAuthState{
			State:      stateID,
			ProviderID: "google",
			CreatedAt:  time.Now().Add(-20 * time.Minute),
			ExpiresAt:  time.Now().Add(-10 * time.Minute),
		}
		storage.Store(ctx, stateID, expiredState, -10*time.Minute)
	}

	// Add some valid states
	for i := 0; i < 2; i++ {
		stateID := fmt.Sprintf("valid-state-%d", i)
		validState := &OAuthState{
			State:      stateID,
			ProviderID: "google",
			CreatedAt:  time.Now(),
			ExpiresAt:  time.Now().Add(10 * time.Minute),
		}
		storage.Store(ctx, stateID, validState, 10*time.Minute)
	}

	// Cleanup expired states
	count, err := storage.CleanupExpired(ctx)
	if err != nil {
		t.Fatalf("failed to cleanup expired states: %v", err)
	}

	if count != 3 {
		t.Errorf("expected to cleanup 3 expired states, got %d", count)
	}

	// Verify total count is now 2 (only valid states remain)
	totalCount, err := storage.Count(ctx)
	if err != nil {
		t.Fatalf("failed to get count: %v", err)
	}

	if totalCount != 2 {
		t.Errorf("expected 2 remaining states, got %d", totalCount)
	}
}

func TestInMemoryOAuthStateStorage_Count(t *testing.T) {
	storage := NewInMemoryOAuthStateStorage(100 * time.Millisecond)
	defer storage.Close()

	ctx := context.Background()

	// Initially should be 0
	count, err := storage.Count(ctx)
	if err != nil {
		t.Fatalf("failed to get count: %v", err)
	}
	if count != 0 {
		t.Errorf("expected initial count to be 0, got %d", count)
	}

	// Add some states
	for i := 0; i < 5; i++ {
		stateID := fmt.Sprintf("test-state-%d", i)
		state := &OAuthState{
			State:      stateID,
			ProviderID: "google",
			CreatedAt:  time.Now(),
			ExpiresAt:  time.Now().Add(10 * time.Minute),
		}
		storage.Store(ctx, stateID, state, 10*time.Minute)
	}

	// Count should be 5
	count, err = storage.Count(ctx)
	if err != nil {
		t.Fatalf("failed to get count: %v", err)
	}
	if count != 5 {
		t.Errorf("expected count to be 5, got %d", count)
	}
}

func TestInMemoryOAuthStateStorage_BackgroundCleanup(t *testing.T) {
	// Use very short cleanup interval for testing
	storage := NewInMemoryOAuthStateStorage(50 * time.Millisecond)
	defer storage.Close()

	ctx := context.Background()

	// Add expired state
	expiredState := &OAuthState{
		State:      "expired-state",
		ProviderID: "google",
		CreatedAt:  time.Now().Add(-20 * time.Minute),
		ExpiresAt:  time.Now().Add(-10 * time.Minute),
	}
	storage.Store(ctx, "expired-state", expiredState, -10*time.Minute)

	// Add valid state
	validState := &OAuthState{
		State:      "valid-state",
		ProviderID: "google",
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(10 * time.Minute),
	}
	storage.Store(ctx, "valid-state", validState, 10*time.Minute)

	// Wait for background cleanup to run
	time.Sleep(150 * time.Millisecond)

	// Only valid state should remain
	count, err := storage.Count(ctx)
	if err != nil {
		t.Fatalf("failed to get count: %v", err)
	}

	if count != 1 {
		t.Errorf("expected 1 state after background cleanup, got %d", count)
	}

	// Verify the remaining state is the valid one
	_, err = storage.Retrieve(ctx, "valid-state")
	if err != nil {
		t.Error("valid state should still exist")
	}

	// Expired state should be gone
	_, err = storage.Retrieve(ctx, "expired-state")
	if err == nil {
		t.Error("expired state should be cleaned up")
	}
}
