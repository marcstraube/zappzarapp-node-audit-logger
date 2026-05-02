# GDPR Compliance

> How `@zappzarapp/audit-logger` supports GDPR compliance

## GDPR Articles Covered

| Article      | Requirement           | How This Package Helps                                 |
| ------------ | --------------------- | ------------------------------------------------------ |
| Art. 5(1)(e) | Storage limitation    | Package does not implement purge (see Retention below) |
| Art. 15      | Right of access       | `getLogsForUser()` retrieves all actions on a user     |
| Art. 17      | Right to erasure      | Audit trail of deletion via `log()`                    |
| Art. 30      | Records of processing | Complete audit trail of data access and modifications  |
| Art. 32      | Security measures     | Encrypted data, tamper-proof checksums, append-only    |
| Art. 33      | Breach notification   | `getLogsForEntity()` shows what data was accessed      |

## Data Encryption

All additional data (user agent, changed fields, context) is encrypted at rest:

- **AppEncryption** (default): AES-256-GCM encryption via node:crypto, stored as
  base64
- **DatabaseEncryption**: Uses database-level `encrypt_text()` functions

See [database-encryption.md](./database-encryption.md) for migration guidance.

## Tamper Detection

Every audit log entry includes a SHA-256 checksum:

```text
checksum = SHA256(timestamp + action + entity_type + entity_id + data_json)
```

Use `verify()` to detect tampered entries:

```typescript
const logs = await auditLogger.getLogsForEntity('user', 123);
for (const log of logs) {
  if (!auditLogger.verify(log)) {
    // Entry has been tampered with!
  }
}
```

## Immutability

The database migrations include triggers that prevent `UPDATE` and `DELETE`
operations on the audit_logs table. Entries can only be inserted.

## Purge / Data Retention

This package **does not implement purge functionality**. This is intentional:

- Retention periods vary by jurisdiction and industry
- Purging audit logs requires careful legal review
- The decision to delete audit data should be explicit, not automatic

### Recommended Retention Periods

| Data Type             | Period             | Rationale                                |
| --------------------- | ------------------ | ---------------------------------------- |
| Audit logs            | 2 years (730 days) | Legal compliance, incident investigation |
| Failed login attempts | 90 days            | Security monitoring                      |
| Financial records     | 7-10 years         | Tax/legal requirements                   |

### Implementing Purge

When you need to purge old audit logs, disable the immutability trigger
temporarily:

**PostgreSQL:**

```sql
-- Disable trigger for cleanup
ALTER TABLE audit_logs DISABLE TRIGGER audit_logs_no_delete;

-- Delete logs older than 2 years
DELETE FROM audit_logs WHERE timestamp < NOW() - INTERVAL '730 days';

-- Re-enable trigger
ALTER TABLE audit_logs ENABLE TRIGGER audit_logs_no_delete;
```

**MariaDB:**

```sql
-- Drop trigger temporarily
DROP TRIGGER IF EXISTS audit_logs_no_delete;

-- Delete old logs
DELETE FROM audit_logs WHERE timestamp < NOW() - INTERVAL 730 DAY;

-- Recreate trigger
DELIMITER $$
CREATE TRIGGER audit_logs_no_delete
    BEFORE DELETE ON audit_logs
    FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000'
    SET MESSAGE_TEXT = 'Audit logs are immutable and cannot be deleted';
END$$
DELIMITER ;
```

### Scheduling Cleanup

**System cron (recommended):**

```bash
# /etc/cron.d/audit-log-cleanup
# Run daily at 3 AM
0 3 * * * root /path/to/cleanup-script.sh >> /var/log/audit-cleanup.log 2>&1
```

**PostgreSQL pg_cron:**

```sql
SELECT cron.schedule('cleanup-audit-logs', '0 3 * * *',
    $$DELETE FROM audit_logs WHERE timestamp < NOW() - INTERVAL '730 days'$$);
```

## Subject Access Request (SAR)

When a user requests their data (GDPR Art. 15):

```typescript
const logs = await auditLogger.getLogsForUser(userId);

// Log the export request itself
await auditLogger.log({
  action: 'user.export',
  entityType: 'user',
  entityId: userId,
  userId: requestingUserId,
  data: { reason: 'GDPR Subject Access Request (Art. 15)' },
});
```

## Best Practices

1. **Log context, not sensitive data** - Record what changed, not the actual
   values
2. **Always include user ID** - Essential for SAR compliance
3. **Use consistent action names** - Follow `{entity}.{action}` convention
4. **Log deletion reasons** - Required for Art. 17 compliance proof
5. **Verify checksums periodically** - Detect tampering early
