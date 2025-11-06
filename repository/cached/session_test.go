package cached

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/GoBetterAuth/go-better-auth/domain/session"
	"github.com/GoBetterAuth/go-better-auth/domain/user"
	"github.com/GoBetterAuth/go-better-auth/storage"
	gobetterauthtests "github.com/GoBetterAuth/go-better-auth/tests"
)

func setupTestSessionRepository(t *testing.T) (session.Repository, user.Repository) {
	t.Helper()

	testRepos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	t.Cleanup(cleanup)

	return testRepos.SessionRepo, testRepos.UserRepo
}

func TestCachedSessionRepository_Create(t *testing.T) {
	primary, userRepo := setupTestSessionRepository(t)
	secondary := storage.NewInMemorySecondaryStorage()
	repo := NewSessionRepository(primary, secondary)

	// Create a user first to satisfy foreign key constraint
	testUser := gobetterauthtests.CreateTestUser()
	err := userRepo.Create(testUser)
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	sess := &session.Session{
		ID:        uuid.New().String(),
		UserID:    testUser.ID,
		Token:     "token123",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	err = repo.Create(sess)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify it was stored in primary
	found, err := primary.FindByToken(sess.Token)
	if err != nil {
		t.Fatalf("expected to find session in primary, got error: %v", err)
	}
	if found.Token != sess.Token {
		t.Errorf("expected token %s, got %s", sess.Token, found.Token)
	}
}

func TestCachedSessionRepository_FindByToken_CacheHit(t *testing.T) {
	primary, userRepo := setupTestSessionRepository(t)
	secondary := storage.NewInMemorySecondaryStorage()
	repo := NewSessionRepository(primary, secondary)

	// Create a user first to satisfy foreign key constraint
	testUser := gobetterauthtests.CreateTestUser()
	err := userRepo.Create(testUser)
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	sess := &session.Session{
		ID:        uuid.New().String(),
		UserID:    testUser.ID,
		Token:     "token123",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Create session
	if err := repo.Create(sess); err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// First lookup should cache it
	found1, err := repo.FindByToken(sess.Token)
	if err != nil {
		t.Fatalf("expected to find session, got error: %v", err)
	}
	if found1.Token != sess.Token {
		t.Errorf("expected token %s, got %s", sess.Token, found1.Token)
	}

	// Delete from primary storage to verify cache is used
	if err := primary.Delete(sess.ID); err != nil {
		t.Fatalf("failed to delete from primary: %v", err)
	}

	// Second lookup should come from cache
	found2, err := repo.FindByToken(sess.Token)
	if err != nil {
		t.Fatalf("expected to find session in cache, got error: %v", err)
	}
	if found2.Token != sess.Token {
		t.Errorf("expected token %s, got %s", sess.Token, found2.Token)
	}
}

func TestCachedSessionRepository_Delete(t *testing.T) {
	primary, userRepo := setupTestSessionRepository(t)
	secondary := storage.NewInMemorySecondaryStorage()
	repo := NewSessionRepository(primary, secondary)

	// Create a user first to satisfy foreign key constraint
	testUser := gobetterauthtests.CreateTestUser()
	err := userRepo.Create(testUser)
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	sess := &session.Session{
		ID:        uuid.New().String(),
		UserID:    testUser.ID,
		Token:     "token123",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Create and cache
	if err := repo.Create(sess); err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// Verify it's cached
	_, err = repo.FindByToken(sess.Token)
	if err != nil {
		t.Fatalf("expected to find session, got error: %v", err)
	}

	// Delete
	if err := repo.Delete(sess.ID); err != nil {
		t.Fatalf("failed to delete session: %v", err)
	}

	// Verify it's deleted from primary
	deletedSess, err := primary.FindByToken(sess.Token)
	if err != nil {
		t.Fatalf("unexpected error from primary repository: %v", err)
	}
	if deletedSess != nil {
		t.Error("expected session to be deleted from primary, but it still exists")
	}
}

func TestCachedSessionRepository_Update(t *testing.T) {
	primary, userRepo := setupTestSessionRepository(t)
	secondary := storage.NewInMemorySecondaryStorage()
	repo := NewSessionRepository(primary, secondary)

	// Create a user first to satisfy foreign key constraint
	testUser := gobetterauthtests.CreateTestUser()
	err := userRepo.Create(testUser)
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	sess := &session.Session{
		ID:        uuid.New().String(),
		UserID:    testUser.ID,
		Token:     "token123",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Create
	if err := repo.Create(sess); err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// Update expiration
	sess.ExpiresAt = time.Now().Add(2 * time.Hour)
	if err := repo.Update(sess); err != nil {
		t.Fatalf("failed to update session: %v", err)
	}

	// Verify cache was updated
	found, err := repo.FindByToken(sess.Token)
	if err != nil {
		t.Fatalf("expected to find session, got error: %v", err)
	}

	// Check that the expiration is close to what we set
	diff := found.ExpiresAt.Sub(sess.ExpiresAt)
	if diff < -time.Second || diff > time.Second {
		t.Errorf("expected expiration around %v, got %v", sess.ExpiresAt, found.ExpiresAt)
	}
}
