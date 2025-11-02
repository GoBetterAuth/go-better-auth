package sqlite

import (
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/GoBetterAuth/go-better-auth/domain/verification"
	"github.com/GoBetterAuth/go-better-auth/internal/crypto"
)

// VerificationRepository implements verification.Repository for SQLite
type VerificationRepository struct {
	db         *sql.DB
	logQueries bool
}

// NewVerificationRepository creates a new SQLite verification repository
func NewVerificationRepository(db *sql.DB, logQueries bool) *VerificationRepository {
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

	query := `
		INSERT INTO verifications (user_id, identifier, token, type, expires_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	_, err := r.db.Exec(query, v.UserID, v.Identifier, v.Token, v.Type, v.ExpiresAt, v.CreatedAt, v.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to create verification: %w", err)
	}

	return nil
}

// FindByID retrieves a verification record by ID
func (r *VerificationRepository) FindByID(id string) (*verification.Verification, error) {
	query := `
		SELECT id, user_id, identifier, token, type, expires_at, created_at, updated_at
		FROM verifications
		WHERE id = ?
	`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	var v verification.Verification
	err := r.db.QueryRow(query, id).Scan(
		&v.ID, &v.UserID, &v.Identifier, &v.Token, &v.Type, &v.ExpiresAt, &v.CreatedAt, &v.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("verification not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query verification: %w", err)
	}

	return &v, nil
}

// FindByToken retrieves a verification record by token
func (r *VerificationRepository) FindByToken(token string) (*verification.Verification, error) {
	query := `
		SELECT id, user_id, identifier, token, type, expires_at, created_at, updated_at
		FROM verifications
		WHERE token = ?
	`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	var v verification.Verification
	err := r.db.QueryRow(query, token).Scan(
		&v.ID, &v.UserID, &v.Identifier, &v.Token, &v.Type, &v.ExpiresAt, &v.CreatedAt, &v.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("verification token not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query verification: %w", err)
	}

	return &v, nil
}

// FindByHashedToken retrieves a verification record by matching a plain token against a hashed token
func (r *VerificationRepository) FindByHashedToken(plainToken string) (*verification.Verification, error) {
	query := `
		SELECT id, user_id, identifier, token, type, expires_at, created_at, updated_at
		FROM verifications
		ORDER BY created_at DESC
	`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	rows, err := r.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query verifications: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var v verification.Verification
		err := rows.Scan(
			&v.ID, &v.UserID, &v.Identifier, &v.Token, &v.Type, &v.ExpiresAt, &v.CreatedAt, &v.UpdatedAt,
		)
		if err != nil {
			continue
		}

		if crypto.VerifyVerificationToken(plainToken, v.Token) {
			return &v, nil
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate verifications: %w", err)
	}

	return nil, fmt.Errorf("verification token not found")
}

// FindByIdentifierAndType retrieves a verification record by identifier and type
func (r *VerificationRepository) FindByIdentifierAndType(identifier string, verType verification.VerificationType) (*verification.Verification, error) {
	query := `
		SELECT id, user_id, identifier, token, type, expires_at, created_at, updated_at
		FROM verifications
		WHERE identifier = ? AND type = ?
	`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	var v verification.Verification
	err := r.db.QueryRow(query, identifier, verType).Scan(
		&v.ID, &v.UserID, &v.Identifier, &v.Token, &v.Type, &v.ExpiresAt, &v.CreatedAt, &v.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("verification not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query verification: %w", err)
	}

	return &v, nil
}

// FindByIdentifier retrieves all verification records for an identifier
func (r *VerificationRepository) FindByIdentifier(identifier string) ([]*verification.Verification, error) {
	query := `
		SELECT id, user_id, identifier, token, type, expires_at, created_at, updated_at
		FROM verifications
		WHERE identifier = ?
		ORDER BY created_at DESC
	`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	rows, err := r.db.Query(query, identifier)
	if err != nil {
		return nil, fmt.Errorf("failed to query verifications: %w", err)
	}
	defer rows.Close()

	var verifications []*verification.Verification
	for rows.Next() {
		var v verification.Verification
		err := rows.Scan(
			&v.ID, &v.UserID, &v.Identifier, &v.Token, &v.Type, &v.ExpiresAt, &v.CreatedAt, &v.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan verification: %w", err)
		}
		verifications = append(verifications, &v)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	return verifications, nil
}

// Update updates an existing verification record
func (r *VerificationRepository) Update(v *verification.Verification) error {
	if v == nil {
		return fmt.Errorf("verification cannot be nil")
	}

	query := `
		UPDATE verifications
		SET user_id = ?, identifier = ?, token = ?, type = ?, expires_at = ?, updated_at = ?
		WHERE id = ?
	`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	result, err := r.db.Exec(query, v.UserID, v.Identifier, v.Token, v.Type, v.ExpiresAt, v.UpdatedAt, v.ID)
	if err != nil {
		return fmt.Errorf("failed to update verification: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("verification not found")
	}

	return nil
}

// Delete deletes a verification record by ID
func (r *VerificationRepository) Delete(id string) error {
	query := `DELETE FROM verifications WHERE id = ?`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	result, err := r.db.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to delete verification: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("verification not found")
	}

	return nil
}

// DeleteByIdentifierAndType deletes a verification record by identifier and type
func (r *VerificationRepository) DeleteByToken(token string) error {
	query := `DELETE FROM verifications WHERE token = ?`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	result, err := r.db.Exec(query, token)
	if err != nil {
		return fmt.Errorf("failed to delete verification: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("verification not found")
	}

	return nil
}

// DeleteByIdentifierAndType deletes a verification record by identifier and type (for internal use)
func (r *VerificationRepository) deleteByIdentifierAndType(identifier string, verType verification.VerificationType) error {
	query := `DELETE FROM verifications WHERE identifier = ? AND type = ?`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	result, err := r.db.Exec(query, identifier, verType)
	if err != nil {
		return fmt.Errorf("failed to delete verification: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("verification not found")
	}

	return nil
}

// DeleteExpired deletes all expired verification records
func (r *VerificationRepository) DeleteExpired() error {
	query := `DELETE FROM verifications WHERE expires_at < ?`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	_, err := r.db.Exec(query, time.Now())
	if err != nil {
		return fmt.Errorf("failed to delete expired verifications: %w", err)
	}

	return nil
}

// Count returns the total number of verification records
func (r *VerificationRepository) Count() (int, error) {
	query := `SELECT COUNT(*) FROM verifications`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	var count int
	err := r.db.QueryRow(query).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count verifications: %w", err)
	}

	return count, nil
}

// ExistsByID checks if a verification record exists by ID
func (r *VerificationRepository) ExistsByID(id string) (bool, error) {
	query := `SELECT COUNT(*) FROM verifications WHERE id = ?`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	var count int
	err := r.db.QueryRow(query, id).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check verification existence: %w", err)
	}

	return count > 0, nil
}

// ExistsByToken checks if a verification record exists by token
func (r *VerificationRepository) ExistsByToken(token string) (bool, error) {
	query := `SELECT COUNT(*) FROM verifications WHERE token = ?`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	var count int
	err := r.db.QueryRow(query, token).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check verification existence: %w", err)
	}

	return count > 0, nil
}

// ExistsByIdentifierAndType checks if a verification record exists by identifier and type
func (r *VerificationRepository) ExistsByIdentifierAndType(identifier string, verType verification.VerificationType) (bool, error) {
	query := `SELECT COUNT(*) FROM verifications WHERE identifier = ? AND type = ?`

	if r.logQueries {
		slog.Debug("executing query", "query", query)
	}

	var count int
	err := r.db.QueryRow(query, identifier, verType).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check verification existence: %w", err)
	}

	return count > 0, nil
}
