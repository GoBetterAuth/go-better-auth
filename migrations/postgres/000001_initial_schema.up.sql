-- Go Better Auth Database Schema (PostgreSQL)
-- Enable UUIDs
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------------------------
-- FUNCTIONS
-- ---------------------------

-- Create a function to automatically update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ language 'plpgsql';

-- ---------------------------
-- USERS
-- ---------------------------

CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(255) NOT NULL,
  email VARCHAR(255) UNIQUE NOT NULL,
  email_verified BOOLEAN DEFAULT FALSE,
  image TEXT,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

DROP TRIGGER IF EXISTS update_users_updated_at ON users;
CREATE TRIGGER update_users_updated_at
  BEFORE UPDATE ON users
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

-- ---------------------------
-- SESSIONS
-- ---------------------------

CREATE TABLE IF NOT EXISTS sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  token VARCHAR(512) UNIQUE NOT NULL,
  ip_address VARCHAR(45),
  user_agent TEXT,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
  CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

DROP TRIGGER IF EXISTS update_sessions_updated_at ON sessions;
CREATE TRIGGER update_sessions_updated_at
  BEFORE UPDATE ON sessions
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

-- ---------------------------
-- ACCOUNTS (for credentials and OAuth providers)
-- ---------------------------

CREATE TABLE IF NOT EXISTS accounts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  account_id VARCHAR(255) NOT NULL,
  provider_id VARCHAR(255) NOT NULL,
  access_token TEXT,
  refresh_token TEXT,
  id_token TEXT,
  access_token_expires_at TIMESTAMP,
  refresh_token_expires_at TIMESTAMP,
  scope TEXT,
  password TEXT,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
  CONSTRAINT fk_accounts_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT unique_provider_account UNIQUE(account_id, provider_id)
);

CREATE INDEX IF NOT EXISTS idx_accounts_user_id ON accounts(user_id);
CREATE INDEX IF NOT EXISTS idx_accounts_account_provider ON accounts(account_id, provider_id);

DROP TRIGGER IF EXISTS update_accounts_updated_at ON accounts;
CREATE TRIGGER update_accounts_updated_at
  BEFORE UPDATE ON accounts
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

-- ---------------------------
-- VERIFICATIONS (for email verification, password reset tokens, and email change tokens)
-- ---------------------------

CREATE TABLE IF NOT EXISTS verifications (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID,
  identifier VARCHAR(255) NOT NULL,
  token VARCHAR(512) UNIQUE NOT NULL,
  type VARCHAR(50) NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
  CONSTRAINT fk_verifications_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_verifications_user_id ON verifications(user_id);
CREATE INDEX IF NOT EXISTS idx_verifications_identifier ON verifications(identifier);
CREATE INDEX IF NOT EXISTS idx_verifications_token ON verifications(token);
CREATE INDEX IF NOT EXISTS idx_verifications_type ON verifications(type);
CREATE INDEX IF NOT EXISTS idx_verifications_expires_at ON verifications(expires_at);

-- ---------------------------
-- SECONDARY STORAGE (key-value storage e.g. sessions, rate limiting, etc.)
-- ---------------------------

CREATE TABLE IF NOT EXISTS secondary_storage (
  key VARCHAR(255) PRIMARY KEY,
  value TEXT NOT NULL,
  expires_at TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_secondary_storage_expires_at ON secondary_storage(expires_at);

DROP TRIGGER IF EXISTS update_secondary_storage_updated_at ON secondary_storage;
CREATE TRIGGER update_secondary_storage_updated_at
  BEFORE UPDATE ON secondary_storage
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();
  
-- ---------------------------
-- TWO FACTOR AUTH (for storing MFA configurations) (WIP)
-- ---------------------------

CREATE TABLE IF NOT EXISTS two_factor_auth (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL UNIQUE,
  method VARCHAR(50) NOT NULL DEFAULT 'totp',
  is_enabled BOOLEAN DEFAULT FALSE,
  backup_codes JSONB DEFAULT '[]',
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
  verified_at TIMESTAMP,
  disabled_at TIMESTAMP,
  CONSTRAINT fk_two_factor_auth_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_two_factor_auth_user_id ON two_factor_auth(user_id);
CREATE INDEX IF NOT EXISTS idx_two_factor_auth_method ON two_factor_auth(method);

DROP TRIGGER IF EXISTS update_two_factor_auth_updated_at ON two_factor_auth;
CREATE TRIGGER update_two_factor_auth_updated_at
  BEFORE UPDATE ON two_factor_auth
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

-- ---------------------------
-- TOTP SECRETS (for storing TOTP-specific secrets)
-- ---------------------------

CREATE TABLE IF NOT EXISTS totp_secrets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  secret VARCHAR(255) NOT NULL,
  qr_code TEXT,
  backup_codes JSONB DEFAULT '[]',
  is_verified BOOLEAN DEFAULT FALSE,
  verification_count INTEGER DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
  verified_at TIMESTAMP,
  CONSTRAINT fk_totp_secrets_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_totp_secrets_user_id ON totp_secrets(user_id);
CREATE INDEX IF NOT EXISTS idx_totp_secrets_created_at ON totp_secrets(created_at DESC);

DROP TRIGGER IF EXISTS update_totp_secrets_updated_at ON totp_secrets;
CREATE TRIGGER update_totp_secrets_updated_at
  BEFORE UPDATE ON totp_secrets
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

-- ---------------------------
-- MFA CHALLENGES (for storing pending MFA challenges during login)
-- ---------------------------

CREATE TABLE IF NOT EXISTS mfa_challenges (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  method VARCHAR(50) NOT NULL DEFAULT 'totp',
  challenge VARCHAR(512),
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  CONSTRAINT fk_mfa_challenges_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_mfa_challenges_user_id ON mfa_challenges(user_id);
CREATE INDEX IF NOT EXISTS idx_mfa_challenges_method ON mfa_challenges(method);
CREATE INDEX IF NOT EXISTS idx_mfa_challenges_expires_at ON mfa_challenges(expires_at);

-- ---------------------------
-- CSRF TOKENS
-- ---------------------------

CREATE TABLE IF NOT EXISTS csrf_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  token VARCHAR(255) UNIQUE NOT NULL,
  secret VARCHAR(255) NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_csrf_expires_at ON csrf_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_csrf_token ON csrf_tokens(token);

-- Create a cleanup function for expired records
CREATE OR REPLACE FUNCTION cleanup_expired_records()
RETURNS void AS $$
BEGIN
  -- Delete expired sessions
  DELETE FROM sessions WHERE expires_at < NOW();
  
  -- Delete expired verifications
  DELETE FROM verifications WHERE expires_at < NOW();

  -- Delete expired MFA challenges
  DELETE FROM mfa_challenges WHERE expires_at < NOW();
END;
$$ LANGUAGE plpgsql;

-- ---------------------------
-- OAUTH STATES (for storing OAuth state storage)
-- ---------------------------

CREATE TABLE IF NOT EXISTS oauth_states (
  id VARCHAR(255) PRIMARY KEY,
  state_data TEXT NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_oauth_states_expires_at ON oauth_states(expires_at);

-- ---------------------------
-- COMMENTS
-- ---------------------------

COMMENT ON TABLE users IS 'Stores user account information';
COMMENT ON TABLE sessions IS 'Stores active user sessions';
COMMENT ON TABLE accounts IS 'Stores authentication provider accounts (credentials and OAuth)';
COMMENT ON TABLE verifications IS 'Stores temporary verification tokens for email verification and password reset';
COMMENT ON TABLE two_factor_auth IS 'Stores two-factor authentication configurations';
COMMENT ON TABLE totp_secrets IS 'Stores TOTP-specific secrets and backup codes';
COMMENT ON TABLE mfa_challenges IS 'Stores pending MFA challenges during login';
COMMENT ON TABLE csrf_tokens IS 'Stores CSRF tokens for security';
COMMENT ON TABLE secondary_storage IS 'Stores key-value pairs for sessions, rate limiting, and other temporary data';
COMMENT ON TABLE oauth_states IS 'Stores OAuth state data for login flows';
