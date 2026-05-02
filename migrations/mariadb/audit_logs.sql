-- ============================================================================
-- Audit Logs Table (MariaDB)
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
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,

    -- Timestamp (indexed for efficient queries)
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- User who performed the action (NULL for system actions or failed login attempts)
    user_id INT UNSIGNED DEFAULT NULL,

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
    -- With DatabaseEncryption: stores VARBINARY via encrypt_text() function
    data VARBINARY(16000) DEFAULT NULL,

    -- Tamper-proof checksum (HMAC-SHA-256)
    checksum VARCHAR(64) NOT NULL,

    -- Indexes
    INDEX idx_timestamp (timestamp DESC),
    INDEX idx_user_id (user_id, timestamp DESC),
    INDEX idx_entity (entity_type, entity_id, timestamp DESC),
    INDEX idx_action (action, timestamp DESC),
    INDEX idx_failed_login (timestamp DESC, action)

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- IMMUTABILITY TRIGGERS (Append-only table)
-- ============================================================================

DELIMITER $$

DROP TRIGGER IF EXISTS audit_logs_no_update$$
CREATE TRIGGER audit_logs_no_update
    BEFORE UPDATE ON audit_logs
    FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000'
    SET MESSAGE_TEXT = 'Audit logs are immutable and cannot be modified';
END$$

DROP TRIGGER IF EXISTS audit_logs_no_delete$$
CREATE TRIGGER audit_logs_no_delete
    BEFORE DELETE ON audit_logs
    FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000'
    SET MESSAGE_TEXT = 'Audit logs are immutable and cannot be deleted';
END$$

DELIMITER ;

-- ============================================================================
-- COMMENTS
-- ============================================================================

ALTER TABLE audit_logs
    COMMENT = 'GDPR-compliant audit log table (append-only, encrypted data, tamper-proof checksums)';
