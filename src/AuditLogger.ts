import { hkdfSync } from 'node:crypto';
import { AuditLogEntry } from './AuditLogEntry.js';
import type { AuditLogResult } from './AuditLogResult.js';
import type { AuditLoggerInterface } from './AuditLoggerInterface.js';
import { ChecksumCalculator } from './ChecksumCalculator.js';
import { FileLogReader } from './FileLogReader.js';
import { FileLogWriter } from './FileLogWriter.js';
import { ResultMapper, type ResultMapperContext } from './ResultMapper.js';
import type { DatabaseDialect, QueryExecutor } from './QueryExecutor.js';
import { AppEncryption } from './encryption/AppEncryption.js';
import { DatabaseEncryption } from './encryption/DatabaseEncryption.js';
import type { EncryptionInterface } from './encryption/EncryptionInterface.js';
import { AuditLogError } from './exceptions/AuditLogError.js';
import { StorageError } from './exceptions/StorageError.js';
import { HKDF_SALT, toErrorMessage } from './validation.js';

export interface AuditLoggerOptions {
  /** Encryption strategy (default: AppEncryption) */
  readonly encryption?: EncryptionInterface;
  /** Database table name (default: 'audit_logs') */
  readonly tableName?: string;
  /** File path for redundant logging (null = no file logging) */
  readonly logFilePath?: string | null;
  /** Maximum allowed limit for query methods */
  readonly maxLimit?: number;
}

/**
 * GDPR-compliant audit logger with encrypted data storage and tamper-proof HMAC checksums
 *
 * Supports both application-level encryption (AppEncryption) and
 * database-level encryption (DatabaseEncryption via SQL functions).
 * Works with both PostgreSQL and MariaDB/MySQL via the DatabaseDialect parameter.
 */
export class AuditLogger implements AuditLoggerInterface {
  private static readonly DB_HKDF_INFO = 'audit-logger-db-encryption';

  private readonly executor: QueryExecutor;
  private readonly encryptionKey: string;
  private readonly dialect: DatabaseDialect;
  private readonly encryption: EncryptionInterface;
  private readonly validatedTableName: string;
  private readonly logFilePath: string | null;
  private readonly useDbEncryption: boolean;
  private readonly checksumCalculator: ChecksumCalculator;
  private readonly dbEncryptionKey: string;
  private readonly fileLogWriter: FileLogWriter | null;
  private readonly fileLogReader: FileLogReader;
  private readonly maxLimit: number | undefined;

  constructor(
    executor: QueryExecutor,
    encryptionKey: string,
    dialect: DatabaseDialect,
    options?: AuditLoggerOptions
  ) {
    if (Buffer.byteLength(encryptionKey) < 32) {
      throw new AuditLogError('Encryption key must be at least 32 bytes');
    }

    this.executor = executor;
    this.encryptionKey = encryptionKey;
    this.dialect = dialect;
    this.encryption = options?.encryption ?? new AppEncryption();
    const tableName = options?.tableName ?? 'audit_logs';
    this.logFilePath = options?.logFilePath ?? null;
    this.useDbEncryption = this.encryption instanceof DatabaseEncryption;
    this.maxLimit = options?.maxLimit;

    // Stryker disable next-line ConditionalExpression: equivalent — undefined < 1 is false
    if (this.maxLimit !== undefined && this.maxLimit < 1) {
      throw new AuditLogError('maxLimit must be at least 1');
    }

    this.checksumCalculator = new ChecksumCalculator(ChecksumCalculator.deriveKey(encryptionKey));
    this.dbEncryptionKey = this.useDbEncryption
      ? Buffer.from(
          hkdfSync('sha256', encryptionKey, HKDF_SALT, AuditLogger.DB_HKDF_INFO, 32)
        ).toString('hex')
      : /* Stryker disable next-line StringLiteral: equivalent — value unused when !useDbEncryption */ '';
    const fileEncryption = this.useDbEncryption ? new AppEncryption() : this.encryption;
    this.fileLogWriter =
      this.logFilePath !== null
        ? new FileLogWriter(fileEncryption, this.encryptionKey, this.logFilePath)
        : null;
    this.fileLogReader = new FileLogReader(fileEncryption, this.encryptionKey);

    this.validatedTableName = this.validateIdentifier(tableName);
  }

  async log(entry: AuditLogEntry): Promise<void> {
    const timestamp = this.checksumCalculator.formatTimestamp(new Date());

    const dataJson = this.checksumCalculator.encodeData(entry, timestamp);

    const checksum = this.checksumCalculator.calculate({
      timestamp,
      userId: entry.userId,
      ipAddress: entry.ipAddress,
      action: entry.action,
      entityType: entry.entityType,
      entityId: String(entry.entityId),
      dataJson,
    });

    try {
      await this.writeToDatabase(timestamp, entry, dataJson, checksum);
    } catch (dbError) {
      let fileError: unknown = null;
      try {
        await this.fileLogWriter?.write(timestamp, entry, checksum);
      } catch (err) {
        fileError = err;
      }

      const dbMsg = toErrorMessage(dbError);
      if (fileError !== null) {
        /* v8 ignore next -- defensive: Node.js fs always throws Error instances @preserve */
        const fileMsg = toErrorMessage(fileError);
        throw new StorageError(
          `Failed to write audit log to database: ${dbMsg} | File fallback also failed: ${fileMsg}`,
          { cause: dbError }
        );
      }
      throw new StorageError(`Failed to write audit log to database: ${dbMsg}`, {
        cause: dbError,
      });
    }

    try {
      // Stryker disable next-line OptionalChaining: equivalent — fileLogWriter is null only when logFilePath is null
      await this.fileLogWriter?.write(timestamp, entry, checksum);
    } catch {
      // File write is redundant after successful DB write — silently ignore
    }
  }

  async logAuth(
    action: string,
    userId: number | null = null,
    data: Readonly<Record<string, unknown>> = {},
    ipAddress = 'unknown',
    userAgent = 'unknown'
  ): Promise<void> {
    await this.log(
      new AuditLogEntry({
        action,
        entityType: 'auth',
        entityId: String(userId ?? 0),
        userId,
        ipAddress,
        userAgent,
        data,
      })
    );
  }

  async logAdmin(
    action: string,
    adminUserId: number,
    entityType: string,
    entityId: string | number,
    data: Readonly<Record<string, unknown>> = {},
    ipAddress = 'unknown',
    userAgent = 'unknown'
  ): Promise<void> {
    await this.log(
      new AuditLogEntry({
        action,
        entityType,
        entityId,
        userId: adminUserId,
        ipAddress,
        userAgent,
        data: {
          ...data,
          admin_user_id: adminUserId,
        },
      })
    );
  }

  async getLogsForEntity(
    entityType: string,
    entityId: string | number,
    limit = 100
  ): Promise<AuditLogResult[]> {
    return this.queryLogs(
      'entity_type = ? AND entity_id = ?',
      [entityType, String(entityId)],
      limit
    );
  }

  async getLogsForUser(userId: number, limit = 100): Promise<AuditLogResult[]> {
    return this.queryLogs('user_id = ?', [userId], limit);
  }

  verify(result: AuditLogResult): boolean {
    return this.checksumCalculator.verify(result);
  }

  async readFileLog(): Promise<AuditLogResult[]> {
    if (this.logFilePath === null) {
      return [];
    }
    return this.fileLogReader.read(this.logFilePath);
  }

  private async queryLogs(
    whereClause: string,
    whereParams: unknown[],
    limit: number
  ): Promise<AuditLogResult[]> {
    this.validateLimit(limit);

    const dataColumn = this.useDbEncryption ? 'decrypt_text(data, ?) as data_decrypted' : 'data';

    const template = `
      SELECT id, timestamp, user_id, ip_address, action, entity_type, entity_id,
             ${dataColumn}, checksum
      FROM ${this.validatedTableName}
      WHERE ${whereClause}
      ORDER BY timestamp DESC
      LIMIT ?
    `;

    const params: unknown[] = [];
    if (this.useDbEncryption) {
      params.push(this.dbEncryptionKey);
    }
    params.push(...whereParams, limit);

    const sql = this.toDialectSql(template);

    let rows: Record<string, unknown>[];
    try {
      rows = await this.executor.query(sql, params);
    } catch (error) {
      throw new StorageError(`Failed to query audit logs: ${toErrorMessage(error)}`, {
        cause: error,
      });
    }
    return ResultMapper.mapAll(rows, this.resultMapperContext);
  }

  private get resultMapperContext(): ResultMapperContext {
    return {
      useDbEncryption: this.useDbEncryption,
      encryption: this.encryption,
      encryptionKey: this.encryptionKey,
    };
  }

  private async writeToDatabase(
    timestamp: string,
    entry: AuditLogEntry,
    dataJson: string,
    checksum: string
  ): Promise<void> {
    const params: unknown[] = [
      timestamp,
      entry.userId,
      entry.ipAddress,
      entry.action,
      entry.entityType,
      String(entry.entityId),
    ];

    let dataPlaceholder: string;
    if (this.useDbEncryption) {
      dataPlaceholder = 'encrypt_text(?, ?)';
      params.push(dataJson, this.dbEncryptionKey);
    } else {
      dataPlaceholder = '?';
      params.push(this.encryption.encrypt(dataJson, this.encryptionKey));
    }

    params.push(checksum);

    const template = `
      INSERT INTO ${this.validatedTableName} (timestamp, user_id, ip_address, action, entity_type, entity_id, data, checksum)
      VALUES (?, ?, ?, ?, ?, ?, ${dataPlaceholder}, ?)
    `;

    const sql = this.toDialectSql(template);

    await this.executor.execute(sql, params);
  }

  private toDialectSql(template: string): string {
    if (this.dialect === 'postgres') {
      let i = 1;
      return template.replace(/\?/g, () => `$${i++}`);
    }
    return template;
  }

  private validateLimit(limit: number): void {
    if (limit < 1) {
      throw new AuditLogError('Limit must be at least 1');
    }
    // Stryker disable next-line ConditionalExpression: equivalent — undefined > limit is false
    if (this.maxLimit !== undefined && limit > this.maxLimit) {
      throw new AuditLogError(`Limit must not exceed ${this.maxLimit}`);
    }
  }

  /**
   * Validate a SQL identifier (table name) to prevent injection
   */
  private validateIdentifier(identifier: string): string {
    if (identifier.length > 128) {
      throw new StorageError(`Table name exceeds maximum length of 128 characters`);
    }

    if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(identifier)) {
      throw new StorageError(`Invalid table name: ${identifier}`);
    }

    return identifier;
  }
}
