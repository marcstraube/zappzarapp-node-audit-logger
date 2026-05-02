# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-05-02

### Added

#### Core API

- `AuditLoggerInterface` with `log()`, `logAuth()`, `logAdmin()`,
  `getLogsForEntity()`, `getLogsForUser()`, `verify()`, `readFileLog()`
- `AuditLogger` implementation with QueryExecutor, injectable encryption,
  configurable table name, optional file logging
- `NullAuditLogger` no-op implementation (Null Object pattern)
- `AuditLogEntry` immutable input DTO with field validation (byte-length checks,
  non-empty, Object.freeze + structuredClone)
- `AuditLogResult` immutable output type with `dataError` field for corrupted
  data reporting

#### SRP Architecture

- `ChecksumCalculator` — HMAC-SHA256 checksum calculation, envelope encoding,
  integrity verification
- `ResultMapper` — database row to DTO mapping with schema validation and
  envelope parsing
- `FileLogWriter` — encrypted file-based fallback logging with file locking and
  size guard
- `FileLogReader` — programmatic file log recovery with line-level error
  reporting

#### Encryption

- `EncryptionInterface` with two strategies:
  - `AppEncryption` — AES-256-GCM via node:crypto with random 12-byte IV per
    operation (default)
  - `DatabaseEncryption` — Marker for SQL-level
    `encrypt_text()`/`decrypt_text()` functions
- HKDF-SHA256 key derivation with isolated keys for DB encryption, HMAC, and
  file encryption
- Minimum key length enforcement (32 bytes)

#### Integrity & Tamper Detection

- HMAC-SHA256 checksums over all audit-relevant fields (timestamp, userId,
  ipAddress, action, entityType, entityId, dataJson)
- Timing-safe verification via `crypto.timingSafeEqual()`
- Null-byte field separators to prevent delimiter confusion attacks

#### File Fallback & Recovery

- Encrypted file-based fallback logging on database failure
- File locking with O_CREAT|O_EXCL and stale lock detection (60s timeout)
- File permissions 0600, directory permissions 0700 on creation
- File log size limit (10 MB) with rotation hint in error message
- Silent ignore of file write errors after successful DB write
- Combined exception with both error messages when DB and file fallback fail

#### Database Support

- Migration SQL for PostgreSQL and MariaDB with immutability triggers
  (append-only)
- Composite indexes for entity, user, action, and timestamp queries
- Configurable table name with SQL injection prevention (regex-validated
  identifiers, 128-char limit)
- Configurable query limit with optional upper bound (`maxLimit`)

#### GDPR Compliance

- `getLogsForUser()` for Subject Access Requests (Art. 15)
- Audit trail for deletion actions (Art. 17)
- Encryption at rest for all sensitive data (Art. 32)
- Entity-level access history for breach assessment (Art. 33)
- Documentation: `docs/gdpr-compliance.md`, `docs/database-encryption.md`

### Security

- AES-256-GCM with GCM auth tag prevents ciphertext tampering
- HKDF-derived keys — master key never used directly
- No PII in error messages or exception traces
- Parameterized queries for all database operations
- Base64 validation and minimum ciphertext length checks before decryption
- Data size limit (10,000 bytes) prevents oversized payloads
- ESLint security plugin and Secretlint for secret detection

### Quality

- TypeScript strict mode with extended checks (`noUncheckedIndexedAccess`,
  `noImplicitReturns`, `noFallthroughCasesInSwitch`)
- ESLint 10 Flat Config with typescript-eslint, security, sonarjs, jsdoc,
  prettier
- Stryker mutation testing with break: 100
- Vitest 100% coverage (lines, functions, branches, statements)
- dependency-cruiser for architecture enforcement
- 297 tests
- Node.js >= 20, ESM with `"type": "module"`
- Zero runtime dependencies
- Immutable patterns throughout (readonly, Object.freeze, structuredClone)

[1.0.0]:
  https://github.com/marcstraube/zappzarapp-node-audit-logger/releases/tag/v1.0.0
