# ⚡ @zappzarapp/audit-logger

[![CI](https://github.com/marcstraube/zappzarapp-node-audit-logger/actions/workflows/ci.yml/badge.svg)](https://github.com/marcstraube/zappzarapp-node-audit-logger/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/@zappzarapp/audit-logger)](https://www.npmjs.com/package/@zappzarapp/audit-logger)
[![Socket Badge](https://socket.dev/api/badge/npm/package/@zappzarapp/audit-logger)](https://socket.dev/npm/package/@zappzarapp/audit-logger)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/node/v/@zappzarapp/audit-logger)](https://nodejs.org)

GDPR-compliant audit logging for Node.js/TypeScript with injectable encryption,
configurable storage, and tamper-proof checksums.

## Features

- **GDPR compliant** - Supports Art. 15, 17, 30, 32, 33
- **Injectable encryption** - AppEncryption (AES-256-GCM) or DatabaseEncryption
- **Tamper-proof** - SHA-256 checksums with `verify()` method
- **Configurable** - Custom table name, optional file logging
- **Null Object** - `NullAuditLogger` for environments without audit
  requirements
- **Zero runtime dependencies** - Only uses `node:crypto` and `node:fs`
  (built-in)
- **Both PostgreSQL and MariaDB** - Migration SQL included, dialect-aware SQL
  generation
- **DB-agnostic** - `QueryExecutor` interface, no driver dependency

## Installation

```bash
npm install @zappzarapp/audit-logger
```

## Quick Start

```typescript
import { AuditLogger } from '@zappzarapp/audit-logger';

const auditLogger = new AuditLogger(
  executor, // Your QueryExecutor implementation
  process.env.ENCRYPTION_KEY!, // Encryption key
  'postgres' // Database dialect: 'postgres' | 'mysql'
);

// Log a data access event
await auditLogger.log({
  action: 'user.view',
  entityType: 'user',
  entityId: 123,
  userId: currentUserId,
  ipAddress: req.ip,
  userAgent: req.headers['user-agent'],
});

// Log authentication
await auditLogger.logAuth(
  'login.success',
  userId,
  {},
  req.ip,
  req.headers['user-agent']
);

// Log admin action
await auditLogger.logAdmin('role.granted', adminId, 'user', targetUserId, {
  role: 'moderator',
});

// Query logs
const logs = await auditLogger.getLogsForEntity('user', 123);
const userLogs = await auditLogger.getLogsForUser(userId);

// Verify integrity
for (const log of logs) {
  if (!auditLogger.verify(log)) {
    // Tampered entry detected!
  }
}
```

## QueryExecutor Interface

This package does not depend on any database driver. Instead, implement the
`QueryExecutor` interface to wrap your existing connection:

```typescript
import type { QueryExecutor } from '@zappzarapp/audit-logger';

// Example: wrapping a pg Pool
const executor: QueryExecutor = {
  async query(sql, params) {
    const result = await pool.query(sql, params);
    return result.rows;
  },
  async execute(sql, params) {
    const result = await pool.query(sql, params);
    return { affectedRows: result.rowCount ?? 0 };
  },
};
```

## Configuration

```typescript
import {
  AuditLogger,
  AppEncryption,
  DatabaseEncryption,
  NullAuditLogger,
} from '@zappzarapp/audit-logger';

// Full configuration
const auditLogger = new AuditLogger(
  executor,
  process.env.ENCRYPTION_KEY!,
  'postgres',
  {
    encryption: new AppEncryption(), // default (AES-256-GCM via node:crypto)
    tableName: 'audit_logs', // default table name
    logFilePath: '/var/log/audit.log', // optional file logging (null = disabled)
  }
);

// Using database-level encryption (for existing encrypt_text() setups)
const dbLogger = new AuditLogger(
  executor,
  process.env.ENCRYPTION_KEY!,
  'postgres',
  { encryption: new DatabaseEncryption() }
);

// Disable audit logging (Null Object pattern)
const nullLogger = new NullAuditLogger();
```

## Database Setup

Apply the migration for your database:

- **PostgreSQL:** `migrations/postgresql/audit_logs.sql`
- **MariaDB:** `migrations/mariadb/audit_logs.sql`

## Documentation

- [GDPR Compliance](docs/gdpr-compliance.md) - GDPR articles covered,
  purge/retention guidance
- [Database Encryption](docs/database-encryption.md) - Migration from DB-level
  encryption

## Development

```bash
make install    # Install dependencies
make test       # Run tests
make typecheck  # TypeScript type checking
make lint       # ESLint
make build      # Build TypeScript
make check      # All quality checks
```

## License

MIT
