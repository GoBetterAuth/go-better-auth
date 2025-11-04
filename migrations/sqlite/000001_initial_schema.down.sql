-- Rollback initial schema
DROP INDEX IF EXISTS idx_secondary_storage_expires_at;
DROP TABLE IF EXISTS secondary_storage;

DROP INDEX IF EXISTS idx_csrf_token;
DROP INDEX IF EXISTS idx_csrf_expires_at;
DROP TABLE IF EXISTS csrf_tokens;

DROP INDEX IF EXISTS idx_mfa_challenges_expires_at;
DROP INDEX IF EXISTS idx_mfa_challenges_user_id;
DROP TABLE IF EXISTS mfa_challenges;

DROP INDEX IF EXISTS idx_totp_secrets_user_id;
DROP TABLE IF EXISTS totp_secrets;

DROP INDEX IF EXISTS idx_two_factor_auth_user_id;
DROP TABLE IF EXISTS two_factor_auth;

DROP INDEX IF EXISTS idx_verifications_expires_at;
DROP INDEX IF EXISTS idx_verifications_type;
DROP INDEX IF EXISTS idx_verifications_token;
DROP INDEX IF EXISTS idx_verifications_identifier;
DROP INDEX IF EXISTS idx_verifications_user_id;
DROP TABLE IF EXISTS verifications;

DROP INDEX IF EXISTS idx_accounts_provider_account;
DROP INDEX IF EXISTS idx_accounts_user_id;
DROP TABLE IF EXISTS accounts;

DROP INDEX IF EXISTS idx_sessions_expires_at;
DROP INDEX IF EXISTS idx_sessions_user_id;
DROP INDEX IF EXISTS idx_sessions_token;
DROP TABLE IF EXISTS sessions;

DROP INDEX IF EXISTS idx_users_email;
DROP TABLE IF EXISTS users;
