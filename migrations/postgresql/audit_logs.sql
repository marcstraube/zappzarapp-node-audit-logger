-- ============================================================================
-- Audit Logs Table (PostgreSQL)
-- ============================================================================
-- GDPR Art. 30: Records of processing activities
-- GDPR Art. 32: Security measures (logging access to personal data)
--
-- This migration creates the audit_logs table for GDPR-compliant audit logging.
--
-- Note: This migration does NOT include encrypt_text()/decrypt_text() functions.
-- Those are only needed when using DatabaseEncryption strategy.
-- See docs/database-encryption.md for details.
-- ============================================================================

-- Create audit_logs table
CREATE TABLE IF NOT EXISTS audit_logs (
    -- Primary key
    id BIGSERIAL PRIMARY KEY,

    -- Timestamp (indexed for efficient queries)
    timestamp TIMESTAMP NOT NULL DEFAULT NOW(),

    -- User who performed the action (NULL for system actions or failed login attempts)
    user_id INTEGER DEFAULT NULL,

    -- IP address of the client
    ip_address VARCHAR(45) NOT NULL,

    -- Action performed (e.g., 'user.view', 'user.update', 'user.delete', 'login.success')
    action VARCHAR(255) NOT NULL,

    -- Entity type (e.g., 'user', 'order', 'invoice')
    entity_type VARCHAR(100) NOT NULL,

    -- Entity ID (primary key of the entity)
    entity_id VARCHAR(255) NOT NULL,

    -- Additional data (encrypted)
    -- With AppEncryption: stores base64-encoded AES-256-GCM ciphertext
    -- With DatabaseEncryption: stores BYTEA via encrypt_text() function
    data BYTEA,

    -- Tamper-proof checksum (HMAC-SHA-256)
    checksum VARCHAR(64) NOT NULL
);

-- ============================================================================
-- IMMUTABILITY TRIGGERS (Append-only table)
-- ============================================================================

CREATE OR REPLACE FUNCTION prevent_audit_log_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Audit logs are immutable and cannot be modified or deleted';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_logs_no_update ON audit_logs;
CREATE TRIGGER audit_logs_no_update
    BEFORE UPDATE ON audit_logs
    FOR EACH ROW
    EXECUTE FUNCTION prevent_audit_log_modification();

DROP TRIGGER IF EXISTS audit_logs_no_delete ON audit_logs;
CREATE TRIGGER audit_logs_no_delete
    BEFORE DELETE ON audit_logs
    FOR EACH ROW
    EXECUTE FUNCTION prevent_audit_log_modification();

-- ============================================================================
-- INDEXES for performance
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs (user_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_entity ON audit_logs (entity_type, entity_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs (action, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_failed_login ON audit_logs (timestamp DESC) WHERE action = 'login.failed';

-- ============================================================================
-- COMMENTS
-- ============================================================================

COMMENT ON TABLE audit_logs IS 'GDPR-compliant audit log table (append-only, encrypted data, tamper-proof checksums)';
COMMENT ON COLUMN audit_logs.id IS 'Primary key';
COMMENT ON COLUMN audit_logs.timestamp IS 'Timestamp when action was performed';
COMMENT ON COLUMN audit_logs.user_id IS 'User who performed the action (NULL for system actions)';
COMMENT ON COLUMN audit_logs.ip_address IS 'Client IP address';
COMMENT ON COLUMN audit_logs.action IS 'Action performed (e.g., user.view, login.success)';
COMMENT ON COLUMN audit_logs.entity_type IS 'Entity type (e.g., user, order)';
COMMENT ON COLUMN audit_logs.entity_id IS 'Entity ID';
COMMENT ON COLUMN audit_logs.data IS 'Encrypted additional data';
COMMENT ON COLUMN audit_logs.checksum IS 'HMAC-SHA-256 checksum for tamper detection';
