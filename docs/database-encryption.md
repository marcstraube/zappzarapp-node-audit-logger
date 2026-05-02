# Database Encryption Strategy

> Migrating from database-level `encrypt_text()`/`decrypt_text()` functions to
> application-level encryption, or using both strategies.

## Overview

This package supports two encryption strategies:

| Strategy                  | Where Encryption Happens | Dependencies             | Performance      |
| ------------------------- | ------------------------ | ------------------------ | ---------------- |
| `AppEncryption` (default) | Node.js application      | `node:crypto` (built-in) | Single roundtrip |
| `DatabaseEncryption`      | Database SQL functions   | DB functions installed   | Extra SQL calls  |

## AppEncryption (Recommended)

Application-level encryption using AES-256-GCM via node:crypto:

```typescript
import { AuditLogger, AppEncryption } from '@zappzarapp/audit-logger';

const auditLogger = new AuditLogger(
  executor,
  process.env.ENCRYPTION_KEY!,
  'postgres',
  { encryption: new AppEncryption() } // default, can be omitted
);
```

**How it works:**

1. Data is encrypted in Node.js before INSERT
2. Stored as base64-encoded ciphertext in the `data` column
3. On SELECT, raw bytes are fetched and decrypted in Node.js
4. No database functions required

## DatabaseEncryption

For projects that already have `encrypt_text()`/`decrypt_text()` SQL functions
installed (e.g., from the zappzarapp boilerplate):

```typescript
import { AuditLogger, DatabaseEncryption } from '@zappzarapp/audit-logger';

const auditLogger = new AuditLogger(
  executor,
  process.env.ENCRYPTION_KEY!,
  'postgres',
  { encryption: new DatabaseEncryption() }
);
```

**How it works:**

1. INSERT uses `encrypt_text($data, $key)` in SQL
2. SELECT uses `decrypt_text(data, $key)` in SQL
3. Requires `encrypt_text()` and `decrypt_text()` functions in your database

### Required Database Functions

These functions are **not included** in this package's migrations. You must
install them separately. Example implementations:

**PostgreSQL** (requires `pgcrypto`):

```sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE OR REPLACE FUNCTION encrypt_text(p_text TEXT, p_key TEXT)
RETURNS BYTEA AS $$
BEGIN
    RETURN pgp_sym_encrypt(p_text, p_key);
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION decrypt_text(p_data BYTEA, p_key TEXT)
RETURNS TEXT AS $$
BEGIN
    RETURN pgp_sym_decrypt(p_data, p_key);
EXCEPTION WHEN OTHERS THEN
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;
```

**MariaDB:**

```sql
DELIMITER $$

CREATE FUNCTION IF NOT EXISTS encrypt_text(p_text TEXT, p_key VARCHAR(255))
RETURNS VARBINARY(16000) DETERMINISTIC
BEGIN
    RETURN AES_ENCRYPT(p_text, p_key);
END$$

CREATE FUNCTION IF NOT EXISTS decrypt_text(p_data VARBINARY(16000), p_key VARCHAR(255))
RETURNS TEXT DETERMINISTIC
BEGIN
    RETURN AES_DECRYPT(p_data, p_key);
END$$

DELIMITER ;
```

## Migrating from DatabaseEncryption to AppEncryption

If you want to switch from database-level to application-level encryption:

1. **Read all existing data** using DatabaseEncryption (decrypts via SQL)
2. **Re-encrypt with AppEncryption** (encrypts in Node.js)
3. **Update the rows** with new ciphertext

```typescript
import { AppEncryption } from '@zappzarapp/audit-logger';

const appEncryption = new AppEncryption();
const key = process.env.ENCRYPTION_KEY!;

// Temporarily disable immutability trigger (PostgreSQL)
await executor.execute(
  'ALTER TABLE audit_logs DISABLE TRIGGER audit_logs_no_update'
);

const rows = await executor.query(
  `SELECT id, decrypt_text(data, $1) as plaintext FROM audit_logs`,
  [key]
);

for (const row of rows) {
  if (row.plaintext !== null) {
    const encrypted = appEncryption.encrypt(String(row.plaintext), key);
    await executor.execute('UPDATE audit_logs SET data = $1 WHERE id = $2', [
      encrypted,
      row.id,
    ]);
  }
}

// Re-enable trigger
await executor.execute(
  'ALTER TABLE audit_logs ENABLE TRIGGER audit_logs_no_update'
);
```

**Important:** After migration, update your AuditLogger instantiation to use
`AppEncryption` (or omit the encryption option entirely, as it's the default).

## Choosing a Strategy

| Consideration         | AppEncryption           | DatabaseEncryption       |
| --------------------- | ----------------------- | ------------------------ |
| No DB function setup  | Yes                     | No                       |
| Works with any DB     | Yes (via QueryExecutor) | Needs specific functions |
| Encryption key in SQL | No                      | Yes (as parameter)       |
| Single roundtrip      | Yes                     | Yes                      |
| DBA can query data    | No                      | Yes (with key)           |
| Portable backups      | Yes                     | DB-specific              |
