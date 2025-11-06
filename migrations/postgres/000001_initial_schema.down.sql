-- Rollback initial schema for PostgreSQL

-- Remove table comments
COMMENT ON TABLE mfa_challenges IS NULL;
COMMENT ON TABLE csrf_tokens IS NULL;
COMMENT ON TABLE totp_secrets IS NULL;
COMMENT ON TABLE two_factor_auth IS NULL;
COMMENT ON TABLE secondary_storage IS NULL;
COMMENT ON TABLE verifications IS NULL;
COMMENT ON TABLE accounts IS NULL;
COMMENT ON TABLE sessions IS NULL;
COMMENT ON TABLE users IS NULL;

-- Drop cleanup function
DROP FUNCTION IF EXISTS cleanup_expired_records();

-- Drop triggers
DROP TRIGGER IF EXISTS update_totp_secrets_updated_at ON totp_secrets;
DROP TRIGGER IF EXISTS update_two_factor_auth_updated_at ON two_factor_auth;
DROP TRIGGER IF EXISTS update_secondary_storage_updated_at ON secondary_storage;
DROP TRIGGER IF EXISTS update_accounts_updated_at ON accounts;
DROP TRIGGER IF EXISTS update_sessions_updated_at ON sessions;
DROP TRIGGER IF EXISTS update_users_updated_at ON users;

-- Drop the update function
DROP FUNCTION IF EXISTS update_updated_at_column();

-- Drop indexes
DROP INDEX IF EXISTS idx_oauth_states_expires_at;

DROP INDEX IF EXISTS idx_csrf_token;
DROP INDEX IF EXISTS idx_csrf_expires_at;

DROP INDEX IF EXISTS idx_mfa_challenges_expires_at;
DROP INDEX IF EXISTS idx_mfa_challenges_method;
DROP INDEX IF EXISTS idx_mfa_challenges_user_id;

DROP INDEX IF EXISTS idx_totp_secrets_created_at;
DROP INDEX IF EXISTS idx_totp_secrets_user_id;

DROP INDEX IF EXISTS idx_two_factor_auth_method;
DROP INDEX IF EXISTS idx_two_factor_auth_user_id;

DROP INDEX IF EXISTS idx_secondary_storage_expires_at;

DROP INDEX IF EXISTS idx_verifications_expires_at;
DROP INDEX IF EXISTS idx_verifications_type;
DROP INDEX IF EXISTS idx_verifications_token;
DROP INDEX IF EXISTS idx_verifications_identifier;
DROP INDEX IF EXISTS idx_verifications_user_id;

DROP INDEX IF EXISTS idx_accounts_account_provider;
DROP INDEX IF EXISTS idx_accounts_user_id;

DROP INDEX IF EXISTS idx_sessions_expires_at;
DROP INDEX IF EXISTS idx_sessions_user_id;
DROP INDEX IF EXISTS idx_sessions_token;

DROP INDEX IF EXISTS idx_users_email;

-- Drop tables (in reverse order due to foreign keys)
DROP TABLE IF EXISTS oauth_states;
DROP TABLE IF EXISTS csrf_tokens;
DROP TABLE IF EXISTS mfa_challenges;
DROP TABLE IF EXISTS totp_secrets;
DROP TABLE IF EXISTS two_factor_auth;
DROP TABLE IF EXISTS secondary_storage;
DROP TABLE IF EXISTS verifications;
DROP TABLE IF EXISTS accounts;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS users;

-- Drop extension (be careful - this might affect other schemas)
-- DROP EXTENSION IF EXISTS pgcrypto;
