package gorm

import (
	"errors"
	"fmt"
	"log/slog"
	"time"

	"gorm.io/gorm"

	"github.com/GoBetterAuth/go-better-auth/domain/user"
)

// userModel represents the GORM model for the users table
type userModel struct {
	ID            string    `gorm:"primaryKey"`
	Name          string    `gorm:"not null"`
	Email         string    `gorm:"not null;uniqueIndex"`
	EmailVerified bool      `gorm:"default:false"`
	Image         *string   `gorm:"type:text"`
	CreatedAt     time.Time `gorm:"autoCreateTime"`
	UpdatedAt     time.Time `gorm:"autoUpdateTime"`
}

// TableName returns the table name for GORM
func (userModel) TableName() string {
	return "users"
}

// toDomain converts GORM model to domain model
func (m *userModel) toDomain() *user.User {
	return &user.User{
		ID:            m.ID,
		Name:          m.Name,
		Email:         m.Email,
		EmailVerified: m.EmailVerified,
		Image:         m.Image,
		CreatedAt:     m.CreatedAt,
		UpdatedAt:     m.UpdatedAt,
	}
}

// fromDomain converts domain model to GORM model
func (m *userModel) fromDomain(u *user.User) {
	m.ID = u.ID
	m.Name = u.Name
	m.Email = u.Email
	m.EmailVerified = u.EmailVerified
	m.Image = u.Image
	m.CreatedAt = u.CreatedAt
	m.UpdatedAt = u.UpdatedAt
}

// UserRepository implements user.Repository using GORM
type UserRepository struct {
	db         *gorm.DB
	logQueries bool
}

// NewUserRepository creates a new GORM user repository
func NewUserRepository(db *gorm.DB, logQueries bool) *UserRepository {
	return &UserRepository{
		db:         db,
		logQueries: logQueries,
	}
}

// Create creates a new user
func (r *UserRepository) Create(user *user.User) error {
	if user == nil {
		return fmt.Errorf("user cannot be nil")
	}

	var model userModel
	model.fromDomain(user)

	if r.logQueries {
		slog.Debug("creating user", "user_id", user.ID, "email", user.Email)
	}

	if err := r.db.Create(&model).Error; err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	*user = *model.toDomain()

	return nil
}

// FindByID retrieves a user by ID
func (r *UserRepository) FindByID(id string) (*user.User, error) {
	if r.logQueries {
		slog.Debug("finding user by ID", "user_id", id)
	}

	var model userModel
	err := r.db.Where("id = ?", id).First(&model).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, user.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to query user: %w", err)
	}

	return model.toDomain(), nil
}

// FindByEmail retrieves a user by email
func (r *UserRepository) FindByEmail(email string) (*user.User, error) {
	if r.logQueries {
		slog.Debug("finding user by email", "email", email)
	}

	var model userModel
	err := r.db.Where("email = ?", email).First(&model).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, user.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to query user: %w", err)
	}

	return model.toDomain(), nil
}

// Update updates an existing user
func (r *UserRepository) Update(user *user.User) error {
	if user == nil {
		return fmt.Errorf("user cannot be nil")
	}

	if r.logQueries {
		slog.Debug("updating user", "user_id", user.ID)
	}

	var model userModel
	model.fromDomain(user)

	result := r.db.Model(&model).Where("id = ?", user.ID).Updates(&model)
	if result.Error != nil {
		return fmt.Errorf("failed to update user: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

// Delete deletes a user by ID
func (r *UserRepository) Delete(id string) error {
	if r.logQueries {
		slog.Debug("deleting user", "user_id", id)
	}

	result := r.db.Where("id = ?", id).Delete(&userModel{})
	if result.Error != nil {
		return fmt.Errorf("failed to delete user: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

// List retrieves users with pagination
func (r *UserRepository) List(limit int, offset int) ([]*user.User, error) {
	if r.logQueries {
		slog.Debug("listing users", "limit", limit, "offset", offset)
	}

	var models []userModel
	err := r.db.Order("created_at DESC").Limit(limit).Offset(offset).Find(&models).Error
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	users := make([]*user.User, len(models))
	for i, model := range models {
		users[i] = model.toDomain()
	}

	return users, nil
}

// Count returns the total number of users
func (r *UserRepository) Count() (int, error) {
	if r.logQueries {
		slog.Debug("counting total users")
	}

	var count int64
	if err := r.db.Model(&userModel{}).Count(&count).Error; err != nil {
		return 0, fmt.Errorf("failed to count users: %w", err)
	}

	return int(count), nil
}

// ExistsByEmail checks if a user exists by email
func (r *UserRepository) ExistsByEmail(email string) (bool, error) {
	if r.logQueries {
		slog.Debug("checking user existence by email", "email", email)
	}

	var count int64
	if err := r.db.Model(&userModel{}).Where("email = ?", email).Count(&count).Error; err != nil {
		return false, fmt.Errorf("failed to check user existence: %w", err)
	}

	return count > 0, nil
}

// ExistsByID checks if a user exists by ID
func (r *UserRepository) ExistsByID(id string) (bool, error) {
	if r.logQueries {
		slog.Debug("checking user existence by ID", "user_id", id)
	}

	var count int64
	if err := r.db.Model(&userModel{}).Where("id = ?", id).Count(&count).Error; err != nil {
		return false, fmt.Errorf("failed to check user existence: %w", err)
	}

	return count > 0, nil
}
