package gorm

import (
	"errors"
	"fmt"
	"log/slog"
	"time"

	"gorm.io/gorm"

	"github.com/GoBetterAuth/go-better-auth/domain/account"
)

// accountModel represents the GORM model for the accounts table
type accountModel struct {
	ID                    string               `gorm:"primaryKey"`
	UserID                string               `gorm:"not null;index"`
	AccountID             string               `gorm:"not null"`
	ProviderID            account.ProviderType `gorm:"not null"`
	AccessToken           *string              `gorm:"type:text"`
	RefreshToken          *string              `gorm:"type:text"`
	IDToken               *string              `gorm:"type:text"`
	AccessTokenExpiresAt  *time.Time
	RefreshTokenExpiresAt *time.Time
	Scope                 *string   `gorm:"type:text"`
	Password              *string   `gorm:"type:text"`
	CreatedAt             time.Time `gorm:"autoCreateTime"`
	UpdatedAt             time.Time `gorm:"autoUpdateTime"`
}

// TableName returns the table name for GORM
func (accountModel) TableName() string {
	return "accounts"
}

// toDomain converts GORM model to domain model
func (m *accountModel) toDomain() *account.Account {
	return &account.Account{
		ID:                    m.ID,
		UserID:                m.UserID,
		AccountID:             m.AccountID,
		ProviderID:            m.ProviderID,
		AccessToken:           m.AccessToken,
		RefreshToken:          m.RefreshToken,
		IDToken:               m.IDToken,
		AccessTokenExpiresAt:  m.AccessTokenExpiresAt,
		RefreshTokenExpiresAt: m.RefreshTokenExpiresAt,
		Scope:                 m.Scope,
		Password:              m.Password,
		CreatedAt:             m.CreatedAt,
		UpdatedAt:             m.UpdatedAt,
	}
}

// fromDomain converts domain model to GORM model
func (m *accountModel) fromDomain(a *account.Account) {
	m.ID = a.ID
	m.UserID = a.UserID
	m.AccountID = a.AccountID
	m.ProviderID = a.ProviderID
	m.AccessToken = a.AccessToken
	m.RefreshToken = a.RefreshToken
	m.IDToken = a.IDToken
	m.AccessTokenExpiresAt = a.AccessTokenExpiresAt
	m.RefreshTokenExpiresAt = a.RefreshTokenExpiresAt
	m.Scope = a.Scope
	m.Password = a.Password
	m.CreatedAt = a.CreatedAt
	m.UpdatedAt = a.UpdatedAt
}

// AccountRepository implements account.Repository using GORM
type AccountRepository struct {
	db         *gorm.DB
	logQueries bool
}

// NewAccountRepository creates a new GORM account repository
func NewAccountRepository(db *gorm.DB, logQueries bool) *AccountRepository {
	return &AccountRepository{
		db:         db,
		logQueries: logQueries,
	}
}

// Create creates a new account
func (r *AccountRepository) Create(account *account.Account) error {
	if account == nil {
		return fmt.Errorf("account cannot be nil")
	}

	var model accountModel
	model.fromDomain(account)

	if r.logQueries {
		slog.Debug("creating account", "account_id", account.ID, "user_id", account.UserID, "provider", account.ProviderID)
	}

	if err := r.db.Create(&model).Error; err != nil {
		return fmt.Errorf("failed to create account: %w", err)
	}

	*account = *model.toDomain()

	return nil
}

// FindByID retrieves an account by ID
func (r *AccountRepository) FindByID(id string) (*account.Account, error) {
	if r.logQueries {
		slog.Debug("finding account by ID", "account_id", id)
	}

	var model accountModel
	err := r.db.Where("id = ?", id).First(&model).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, account.ErrAccountNotFound
		}
		return nil, fmt.Errorf("failed to query account: %w", err)
	}

	return model.toDomain(), nil
}

// FindByUserIDAndProvider retrieves a user's account for a specific provider
func (r *AccountRepository) FindByUserIDAndProvider(userID string, providerID account.ProviderType) (*account.Account, error) {
	if r.logQueries {
		slog.Debug("finding account by user ID and provider", "user_id", userID, "provider_id", providerID)
	}

	var model accountModel
	err := r.db.Where("user_id = ? AND provider_id = ?", userID, providerID).First(&model).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, account.ErrAccountNotFound
		}
		return nil, fmt.Errorf("failed to query account: %w", err)
	}

	return model.toDomain(), nil
}

// FindByUserID retrieves all accounts for a user
func (r *AccountRepository) FindByUserID(userID string) ([]*account.Account, error) {
	if r.logQueries {
		slog.Debug("finding accounts by user ID", "user_id", userID)
	}

	var models []accountModel
	err := r.db.Where("user_id = ?", userID).Order("created_at DESC").Find(&models).Error
	if err != nil {
		return nil, fmt.Errorf("failed to query accounts: %w", err)
	}

	accounts := make([]*account.Account, len(models))
	for i, model := range models {
		accounts[i] = model.toDomain()
	}

	return accounts, nil
}

// Update updates an existing account
func (r *AccountRepository) Update(account *account.Account) error {
	if account == nil {
		return fmt.Errorf("account cannot be nil")
	}

	if r.logQueries {
		slog.Debug("updating account", "account_id", account.ID)
	}

	var model accountModel
	model.fromDomain(account)

	result := r.db.Model(&model).Where("id = ?", account.ID).Updates(&model)
	if result.Error != nil {
		return fmt.Errorf("failed to update account: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return fmt.Errorf("account not found")
	}

	return nil
}

// Delete deletes an account by ID
func (r *AccountRepository) Delete(id string) error {
	if r.logQueries {
		slog.Debug("deleting account", "account_id", id)
	}

	result := r.db.Where("id = ?", id).Delete(&accountModel{})
	if result.Error != nil {
		return fmt.Errorf("failed to delete account: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return fmt.Errorf("account not found")
	}

	return nil
}

// DeleteByUserID deletes all accounts for a user
func (r *AccountRepository) DeleteByUserID(userID string) error {
	if r.logQueries {
		slog.Debug("deleting accounts by user ID", "user_id", userID)
	}

	if err := r.db.Where("user_id = ?", userID).Delete(&accountModel{}).Error; err != nil {
		return fmt.Errorf("failed to delete accounts: %w", err)
	}

	return nil
}

// Count returns the total number of accounts
func (r *AccountRepository) Count() (int, error) {
	if r.logQueries {
		slog.Debug("counting total accounts")
	}

	var count int64
	if err := r.db.Model(&accountModel{}).Count(&count).Error; err != nil {
		return 0, fmt.Errorf("failed to count accounts: %w", err)
	}

	return int(count), nil
}

// ExistsByID checks if an account exists by ID
func (r *AccountRepository) ExistsByID(id string) (bool, error) {
	if r.logQueries {
		slog.Debug("checking account existence by ID", "account_id", id)
	}

	var count int64
	if err := r.db.Model(&accountModel{}).Where("id = ?", id).Count(&count).Error; err != nil {
		return false, fmt.Errorf("failed to check account existence: %w", err)
	}

	return count > 0, nil
}

// ExistsByUserIDAndProvider checks if a user has an account with the specified provider
func (r *AccountRepository) ExistsByUserIDAndProvider(userID string, providerID account.ProviderType) (bool, error) {
	if r.logQueries {
		slog.Debug("checking account existence by user ID and provider", "user_id", userID, "provider_id", providerID)
	}

	var count int64
	if err := r.db.Model(&accountModel{}).Where("user_id = ? AND provider_id = ?", userID, providerID).Count(&count).Error; err != nil {
		return false, fmt.Errorf("failed to check account existence: %w", err)
	}

	return count > 0, nil
}
