package gorm

import (
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/GoBetterAuth/go-better-auth/domain/verification"
	"github.com/GoBetterAuth/go-better-auth/internal/crypto"
)

// verificationModel represents the GORM model for the verifications table
type verificationModel struct {
	ID         string                        `gorm:"primaryKey"`
	UserID     *string                       `gorm:"index"`
	Identifier string                        `gorm:"not null;index"`
	Token      string                        `gorm:"not null;uniqueIndex"`
	Type       verification.VerificationType `gorm:"not null;index"`
	ExpiresAt  time.Time                     `gorm:"not null"`
	CreatedAt  time.Time                     `gorm:"autoCreateTime"`
	UpdatedAt  time.Time                     `gorm:"autoUpdateTime"`
}

// BeforeCreate generates a UUID for the ID if not set
func (m *verificationModel) BeforeCreate(tx *gorm.DB) (err error) {
	if m.ID == "" {
		m.ID = uuid.New().String()
	}
	return
}

// TableName returns the table name for GORM
func (verificationModel) TableName() string {
	return "verifications"
}

// toDomain converts GORM model to domain model
func (m *verificationModel) toDomain() *verification.Verification {
	var userID string
	if m.UserID != nil {
		userID = *m.UserID
	}
	return &verification.Verification{
		ID:         m.ID,
		UserID:     userID,
		Identifier: m.Identifier,
		Token:      m.Token,
		Type:       m.Type,
		ExpiresAt:  m.ExpiresAt,
		CreatedAt:  m.CreatedAt,
		UpdatedAt:  m.UpdatedAt,
	}
}

// fromDomain converts domain model to GORM model
func (m *verificationModel) fromDomain(v *verification.Verification) {
	m.ID = v.ID
	if v.UserID != "" {
		m.UserID = &v.UserID
	} else {
		m.UserID = nil
	}
	m.Identifier = v.Identifier
	m.Token = v.Token
	m.Type = v.Type
	m.ExpiresAt = v.ExpiresAt
	m.CreatedAt = v.CreatedAt
	m.UpdatedAt = v.UpdatedAt
}

// VerificationRepository implements verification.Repository using GORM
type VerificationRepository struct {
	db         *gorm.DB
	logQueries bool
}

// NewVerificationRepository creates a new GORM verification repository
func NewVerificationRepository(db *gorm.DB, logQueries bool) *VerificationRepository {
	return &VerificationRepository{
		db:         db,
		logQueries: logQueries,
	}
}

// Create creates a new verification record
func (r *VerificationRepository) Create(v *verification.Verification) error {
	if v == nil {
		return fmt.Errorf("verification cannot be nil")
	}

	var model verificationModel
	model.fromDomain(v)

	if r.logQueries {
		slog.Debug("creating verification", "verification_id", v.ID, "user_id", v.UserID, "type", v.Type)
	}

	if err := r.db.Create(&model).Error; err != nil {
		return fmt.Errorf("failed to create verification: %w", err)
	}

	*v = *model.toDomain()

	return nil
}

// FindByID retrieves a verification record by ID
func (r *VerificationRepository) FindByID(id string) (*verification.Verification, error) {
	if r.logQueries {
		slog.Debug("finding verification by ID", "verification_id", id)
	}

	var model verificationModel
	err := r.db.Where("id = ?", id).First(&model).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, verification.ErrVerificationNotFound
		}
		return nil, fmt.Errorf("failed to query verification: %w", err)
	}

	return model.toDomain(), nil
}

// FindByToken retrieves a verification record by token
func (r *VerificationRepository) FindByToken(token string) (*verification.Verification, error) {
	if r.logQueries {
		slog.Debug("finding verification by token", "token", token)
	}

	var model verificationModel
	err := r.db.Where("token = ?", token).First(&model).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, verification.ErrVerificationNotFound
		}
		return nil, fmt.Errorf("failed to query verification: %w", err)
	}

	return model.toDomain(), nil
}

// FindByHashedToken retrieves a verification record by matching a plain token against a hashed token
func (r *VerificationRepository) FindByHashedToken(plainToken string) (*verification.Verification, error) {
	if r.logQueries {
		slog.Debug("finding verification by hashed token")
	}

	var models []verificationModel
	err := r.db.Order("created_at DESC").Find(&models).Error
	if err != nil {
		return nil, fmt.Errorf("failed to query verifications: %w", err)
	}

	for _, model := range models {
		if crypto.VerifyVerificationToken(plainToken, model.Token) {
			return model.toDomain(), nil
		}
	}

	return nil, verification.ErrVerificationNotFound
}

// FindByIdentifierAndType retrieves a verification record by identifier and type
func (r *VerificationRepository) FindByIdentifierAndType(identifier string, verType verification.VerificationType) (*verification.Verification, error) {
	if r.logQueries {
		slog.Debug("finding verification by identifier and type", "identifier", identifier, "type", verType)
	}

	var model verificationModel
	err := r.db.Where("identifier = ? AND type = ?", identifier, verType).First(&model).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, verification.ErrVerificationNotFound
		}
		return nil, fmt.Errorf("failed to query verification: %w", err)
	}

	return model.toDomain(), nil
}

// FindByIdentifier retrieves all verification records for an identifier
func (r *VerificationRepository) FindByIdentifier(identifier string) ([]*verification.Verification, error) {
	if r.logQueries {
		slog.Debug("finding verifications by identifier", "identifier", identifier)
	}

	var models []verificationModel
	err := r.db.Where("identifier = ?", identifier).Order("created_at DESC").Find(&models).Error
	if err != nil {
		return nil, fmt.Errorf("failed to query verifications: %w", err)
	}

	verifications := make([]*verification.Verification, len(models))
	for i, model := range models {
		verifications[i] = model.toDomain()
	}

	return verifications, nil
}

// Update updates an existing verification record
func (r *VerificationRepository) Update(verification *verification.Verification) error {
	if verification == nil {
		return fmt.Errorf("verification cannot be nil")
	}

	if r.logQueries {
		slog.Debug("updating verification", "verification_id", verification.ID)
	}

	var model verificationModel
	model.fromDomain(verification)

	result := r.db.Model(&model).Where("id = ?", verification.ID).Updates(&model)
	if result.Error != nil {
		return fmt.Errorf("failed to update verification: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return fmt.Errorf("verification not found")
	}

	return nil
}

// Delete deletes a verification record by ID
func (r *VerificationRepository) Delete(id string) error {
	if r.logQueries {
		slog.Debug("deleting verification", "verification_id", id)
	}

	result := r.db.Where("id = ?", id).Delete(&verificationModel{})
	if result.Error != nil {
		return fmt.Errorf("failed to delete verification: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return fmt.Errorf("verification not found")
	}

	return nil
}

// DeleteByToken deletes a verification record by token
func (r *VerificationRepository) DeleteByToken(token string) error {
	if r.logQueries {
		slog.Debug("deleting verification by token", "token", token)
	}

	result := r.db.Where("token = ?", token).Delete(&verificationModel{})
	if result.Error != nil {
		return fmt.Errorf("failed to delete verification: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return fmt.Errorf("verification not found")
	}

	return nil
}

// DeleteExpired deletes all expired verification records
func (r *VerificationRepository) DeleteExpired() error {
	if r.logQueries {
		slog.Debug("deleting expired verifications")
	}

	if err := r.db.Where("expires_at < ?", time.Now()).Delete(&verificationModel{}).Error; err != nil {
		return fmt.Errorf("failed to delete expired verifications: %w", err)
	}

	return nil
}

// Count returns the total number of verification records
func (r *VerificationRepository) Count() (int, error) {
	if r.logQueries {
		slog.Debug("counting total verifications")
	}

	var count int64
	if err := r.db.Model(&verificationModel{}).Count(&count).Error; err != nil {
		return 0, fmt.Errorf("failed to count verifications: %w", err)
	}

	return int(count), nil
}

// ExistsByToken checks if a verification record exists by token
func (r *VerificationRepository) ExistsByToken(token string) (bool, error) {
	if r.logQueries {
		slog.Debug("checking verification existence by token", "token", token)
	}

	var count int64
	if err := r.db.Model(&verificationModel{}).Where("token = ?", token).Count(&count).Error; err != nil {
		return false, fmt.Errorf("failed to check verification existence: %w", err)
	}

	return count > 0, nil
}

// ExistsByIdentifierAndType checks if a verification record exists by identifier and type
func (r *VerificationRepository) ExistsByIdentifierAndType(identifier string, verificationType verification.VerificationType) (bool, error) {
	if r.logQueries {
		slog.Debug("checking verification existence by identifier and type", "identifier", identifier, "type", verificationType)
	}

	var count int64
	if err := r.db.Model(&verificationModel{}).Where("identifier = ? AND type = ?", identifier, verificationType).Count(&count).Error; err != nil {
		return false, fmt.Errorf("failed to check verification existence: %w", err)
	}

	return count > 0, nil
}
