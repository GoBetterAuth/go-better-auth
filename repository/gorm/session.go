package gorm

import (
	"errors"
	"fmt"
	"log/slog"
	"time"

	"gorm.io/gorm"

	"github.com/GoBetterAuth/go-better-auth/domain/session"
)

// sessionModel represents the GORM model for the sessions table
type sessionModel struct {
	ID        string    `gorm:"primaryKey"`
	UserID    string    `gorm:"not null;index"`
	ExpiresAt time.Time `gorm:"not null"`
	Token     string    `gorm:"not null;uniqueIndex"`
	IPAddress *string   `gorm:"size:45"`
	UserAgent *string   `gorm:"type:text"`
	CreatedAt time.Time `gorm:"autoCreateTime"`
	UpdatedAt time.Time `gorm:"autoUpdateTime"`
}

// TableName returns the table name for GORM
func (sessionModel) TableName() string {
	return "sessions"
}

// toDomain converts GORM model to domain model
func (m *sessionModel) toDomain() *session.Session {
	return &session.Session{
		ID:        m.ID,
		UserID:    m.UserID,
		ExpiresAt: m.ExpiresAt,
		Token:     m.Token,
		IPAddress: m.IPAddress,
		UserAgent: m.UserAgent,
		CreatedAt: m.CreatedAt,
		UpdatedAt: m.UpdatedAt,
	}
}

// fromDomain converts domain model to GORM model
func (m *sessionModel) fromDomain(s *session.Session) {
	m.ID = s.ID
	m.UserID = s.UserID
	m.ExpiresAt = s.ExpiresAt
	m.Token = s.Token
	m.IPAddress = s.IPAddress
	m.UserAgent = s.UserAgent
	m.CreatedAt = s.CreatedAt
	m.UpdatedAt = s.UpdatedAt
}

// SessionRepository implements session.Repository using GORM
type SessionRepository struct {
	db         *gorm.DB
	logQueries bool
}

// NewSessionRepository creates a new GORM session repository
func NewSessionRepository(db *gorm.DB, logQueries bool) *SessionRepository {
	return &SessionRepository{
		db:         db,
		logQueries: logQueries,
	}
}

// Create creates a new session
func (r *SessionRepository) Create(s *session.Session) error {
	if s == nil {
		return fmt.Errorf("session cannot be nil")
	}

	var model sessionModel
	model.fromDomain(s)

	if r.logQueries {
		slog.Debug("creating session", "session_id", s.ID, "user_id", s.UserID)
	}

	if err := r.db.Create(&model).Error; err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	*s = *model.toDomain()

	return nil
}

// FindByID retrieves a session by ID
func (r *SessionRepository) FindByID(id string) (*session.Session, error) {
	if r.logQueries {
		slog.Debug("finding session by ID", "session_id", id)
	}

	var model sessionModel
	err := r.db.Where("id = ?", id).First(&model).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("session not found")
		}
		return nil, fmt.Errorf("failed to query session: %w", err)
	}

	return model.toDomain(), nil
}

// FindByToken retrieves a session by token
func (r *SessionRepository) FindByToken(token string) (*session.Session, error) {
	if r.logQueries {
		slog.Debug("finding session by token", "token", token)
	}

	var model sessionModel
	err := r.db.Where("token = ?", token).First(&model).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to query session: %w", err)
	}

	return model.toDomain(), nil
}

// FindByUserID retrieves sessions by user ID
func (r *SessionRepository) FindByUserID(userID string) ([]*session.Session, error) {
	if r.logQueries {
		slog.Debug("finding sessions by user ID", "user_id", userID)
	}

	var models []sessionModel
	err := r.db.Where("user_id = ?", userID).Order("created_at DESC").Find(&models).Error
	if err != nil {
		return nil, fmt.Errorf("failed to query sessions: %w", err)
	}

	sessions := make([]*session.Session, len(models))
	for i, model := range models {
		sessions[i] = model.toDomain()
	}

	return sessions, nil
}

// Update updates an existing session
func (r *SessionRepository) Update(session *session.Session) error {
	if session == nil {
		return fmt.Errorf("session cannot be nil")
	}

	if r.logQueries {
		slog.Debug("updating session", "session_id", session.ID)
	}

	var model sessionModel
	model.fromDomain(session)

	result := r.db.Model(&model).Where("id = ?", session.ID).Updates(&model)
	if result.Error != nil {
		return fmt.Errorf("failed to update session: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return fmt.Errorf("session not found")
	}

	return nil
}

// Delete deletes a session by ID
func (r *SessionRepository) Delete(id string) error {
	if r.logQueries {
		slog.Debug("deleting session", "session_id", id)
	}

	result := r.db.Where("id = ?", id).Delete(&sessionModel{})
	if result.Error != nil {
		return fmt.Errorf("failed to delete session: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return fmt.Errorf("session not found")
	}

	return nil
}

// DeleteByUserID deletes all sessions for a user
func (r *SessionRepository) DeleteByUserID(userID string) error {
	if r.logQueries {
		slog.Debug("deleting sessions by user ID", "user_id", userID)
	}

	if err := r.db.Where("user_id = ?", userID).Delete(&sessionModel{}).Error; err != nil {
		return fmt.Errorf("failed to delete sessions: %w", err)
	}

	return nil
}

// DeleteExpired deletes all expired sessions
func (r *SessionRepository) DeleteExpired() error {
	if r.logQueries {
		slog.Debug("deleting expired sessions")
	}

	if err := r.db.Where("expires_at < ?", time.Now()).Delete(&sessionModel{}).Error; err != nil {
		return fmt.Errorf("failed to delete expired sessions: %w", err)
	}

	return nil
}

// Count returns the total number of sessions
func (r *SessionRepository) Count() (int, error) {
	if r.logQueries {
		slog.Debug("counting total sessions")
	}

	var count int64
	if err := r.db.Model(&sessionModel{}).Count(&count).Error; err != nil {
		return 0, fmt.Errorf("failed to count sessions: %w", err)
	}

	return int(count), nil
}

// ExistsByID checks if a session exists by ID
func (r *SessionRepository) ExistsByID(id string) (bool, error) {
	if r.logQueries {
		slog.Debug("checking session existence by ID", "session_id", id)
	}

	var count int64
	if err := r.db.Model(&sessionModel{}).Where("id = ?", id).Count(&count).Error; err != nil {
		return false, fmt.Errorf("failed to check session existence: %w", err)
	}

	return count > 0, nil
}

// ExistsByToken checks if a session exists by token
func (r *SessionRepository) ExistsByToken(token string) (bool, error) {
	if r.logQueries {
		slog.Debug("checking session existence by token", "token", token)
	}

	var count int64
	if err := r.db.Model(&sessionModel{}).Where("token = ?", token).Count(&count).Error; err != nil {
		return false, fmt.Errorf("failed to check session existence: %w", err)
	}

	return count > 0, nil
}
