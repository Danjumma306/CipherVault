-- ============================================================================
-- Deliverable 2: CipherVault Database Schema (PostgreSQL)
-- ============================================================================
-- Matches src/db/schema.ts (managed via Drizzle ORM & Drizzle Kit).
-- Enforces referential integrity, unique per-file user ACL grants, and stores
-- all cryptographic metadata (IV, GCM auth tag, HKDF salt, SHA-256 digest)
-- alongside AES-256-GCM encrypted ciphertext payloads (BYTEA).
-- ============================================================================

-- 1. Users & Role-Based Access Control (RBAC)
CREATE TABLE IF NOT EXISTS users (
  id             TEXT PRIMARY KEY,              -- UUID v4 or Firebase Auth UID
  uid            TEXT UNIQUE,                   -- Firebase Auth UID (Google Sign-In)
  username       TEXT NOT NULL UNIQUE,
  email          TEXT NOT NULL UNIQUE,
  password_hash  TEXT,                          -- bcrypt cost-12 hash (NULL for Google-only users)
  role           TEXT NOT NULL DEFAULT 'member'
                 CHECK (role IN ('admin', 'member', 'viewer')),
  email_verified BOOLEAN NOT NULL DEFAULT FALSE,
  otp_hash       TEXT,                          -- HMAC-SHA256 hash of active 6-digit email OTP
  otp_expires_at TIMESTAMPTZ,                   -- 10-minute OTP expiration timestamp
  otp_attempts   INTEGER NOT NULL DEFAULT 0,    -- Brute-force counter (max 5 attempts)
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2. Encrypted Files & Metadata
-- Plaintext bytes NEVER touch disk or database storage.
-- Ciphertext is encrypted in memory via AES-256-GCM before persisting to BYTEA.
CREATE TABLE IF NOT EXISTS files (
  id               TEXT PRIMARY KEY,           -- UUID v4
  owner_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  original_name    TEXT NOT NULL,
  mime_type        TEXT NOT NULL,
  size_bytes       INTEGER NOT NULL,           -- Plaintext byte length
  storage_filename TEXT NOT NULL UNIQUE,       -- Logical artifact identifier (<uuid>.enc)
  iv_hex           TEXT NOT NULL,              -- 96-bit (24 hex chars) random GCM IV
  auth_tag_hex     TEXT NOT NULL,              -- 128-bit (32 hex chars) GCM auth tag
  salt_hex         TEXT NOT NULL,              -- 128-bit (32 hex chars) HKDF salt
  sha256_hash      TEXT NOT NULL,              -- 256-bit (64 hex chars) SHA-256 of ciphertext
  ciphertext       BYTEA NOT NULL,             -- AES-256-GCM encrypted payload
  tamper_backup    BYTEA,                      -- Snapshot during Security Inspector tamper simulation
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 3. Per-File Access Control Lists (ACL)
-- Controls which non-owner users may decrypt and download a given file.
CREATE TABLE IF NOT EXISTS access_control_lists (
  id         TEXT PRIMARY KEY,                 -- UUID v4
  file_id    TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  permission TEXT NOT NULL DEFAULT 'read'
             CHECK (permission IN ('read', 'write')),
  granted_by TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 4. Security Audit Ledger
-- Records authentication attempts, encrypted uploads, authorized downloads,
-- 403 access denials, and 422 SHA-256/GCM integrity failures.
CREATE TABLE IF NOT EXISTS audit_logs (
  id              TEXT PRIMARY KEY,
  actor_id        TEXT REFERENCES users(id) ON DELETE SET NULL,
  actor_username  TEXT NOT NULL,
  action          TEXT NOT NULL,
  target_file_id  TEXT,
  target_filename TEXT,
  status          TEXT NOT NULL CHECK (status IN ('success', 'denied', 'alert')),
  detail          TEXT NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes & Uniqueness Constraints
CREATE INDEX IF NOT EXISTS idx_files_owner       ON files(owner_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_acl_file_user ON access_control_lists(file_id, user_id);
CREATE INDEX IF NOT EXISTS idx_acl_user          ON access_control_lists(user_id);
CREATE INDEX IF NOT EXISTS idx_acl_file          ON access_control_lists(file_id);
CREATE INDEX IF NOT EXISTS idx_audit_created     ON audit_logs(created_at);
