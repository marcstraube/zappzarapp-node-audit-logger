# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via GitHub's private vulnerability reporting:

1. Go to the
   [Security Advisories page](https://github.com/marcstraube/zappzarapp-node-audit-logger/security/advisories/new)
2. Click "Report a vulnerability"
3. Fill in the details

Alternatively, you can email security concerns to: **<security@marcstraube.de>**

### What to include in your report

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if available)

### Response Timeline

This is currently a solo-maintained project. I will respond as quickly as
possible, typically within a week. Critical vulnerabilities are prioritized.

### Disclosure Policy

- We follow coordinated vulnerability disclosure
- We will credit reporters (unless anonymity is requested)
- Security advisories will be published after fixes are released

## Security Measures

This package implements multiple security layers:

- **Dependency Scanning**: npm audit (production dependencies)
- **Static Analysis**: ESLint with @typescript-eslint, eslint-plugin-security,
  eslint-plugin-sonarjs
- **Secret Detection**: Secretlint for secrets in code
- **Mutation Testing**: Stryker for test quality assurance
- **Automated Updates**: Dependabot for npm + GitHub Actions
- **CI/CD**: GitHub Actions + GitLab CI with security checks on every push

## Known Security Considerations

### Encryption

- **AES-256-GCM** with authenticated encryption (AppEncryption)
- **HKDF key derivation** ensures strong encryption keys regardless of input
  quality
- **Minimum key length** enforced (32 bytes) at construction time
- Random IV per encryption operation prevents ciphertext analysis
- GCM authentication tag prevents tampering with encrypted data

### Database Encryption

When using the `DatabaseEncryption` strategy, the HKDF-derived encryption key is
passed as a SQL parameter to leverage database-native encryption functions
(e.g., `pgp_sym_encrypt` in PostgreSQL, `AES_ENCRYPT` in MariaDB). This is
inherent to the strategy design.

**Trade-off:** The derived key may appear in database query logs, slow query
logs, or statistics views (e.g., `pg_stat_statements`). To mitigate exposure:

- Disable or restrict access to query logging in production
- Use `pg_stat_statements.track_utility = off` (PostgreSQL)
- Use `general_log = OFF` and restrict `slow_query_log` access (MariaDB)
- Ensure database log files have restricted filesystem permissions
- Consider using `AppEncryption` instead if database log exposure is a concern

Note: The key passed is an HKDF-derived key (not the master key), so exposure is
limited to the database encryption scope and does not compromise the master key
or HMAC keys.

### Tamper-Proof Checksums

- **HMAC-SHA-256** covers all audit log fields (timestamp, userId, ipAddress,
  action, entityType, entityId, data)
- Verification via `verify()` method detects any modification to stored records
- Timing-safe comparison via `crypto.timingSafeEqual()` prevents timing attacks

### Log Chain Integrity

Each audit log entry is individually tamper-proof via its HMAC checksum. Entries
are **not** sequentially chained (i.e., each entry's checksum does not include
the previous entry's hash).

**Trade-off:** Sequential chain-linking would detect deletion or reordering of
entries, but requires serialized writes — concurrent inserts would need locking,
significantly impacting performance in high-throughput scenarios.

**Mitigations for deletion/reordering detection:**

- Database triggers can enforce append-only semantics (no UPDATE/DELETE)
- File fallback provides an independent second copy of every entry
- Periodic full verification (`verify()` on all entries) detects any tampering

### File Logging

- File logs are always encrypted via AppEncryption, even when using
  DatabaseEncryption
- File logging serves as an emergency fallback when the database is unavailable
- Log files should be protected by filesystem permissions and external rotation
  (logrotate)
- Note: Node.js `appendFile` does not support file locking (LOCK_EX equivalent).
  In multi-process environments, use external log rotation or a dedicated log
  service.

### Input Validation

- String byte-length validation on all fields matching database column
  constraints
- SQL identifier escaping prevents table name injection
- Parameterized queries prevent SQL injection (PostgreSQL `$1..$N`,
  MySQL/MariaDB `?`)

### API Design

**Security by Default:**

- Encryption key minimum length enforced at construction
- HKDF applied transparently -- no way to bypass key derivation
- File logs encrypted by default -- no plaintext fallback

**Type Safety:**

- Readonly properties prevent modification after creation
- TypeScript strict mode enforced across all files
- Immutable interfaces for audit log entries and results
