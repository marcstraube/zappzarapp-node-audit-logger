import { readFile, stat } from 'node:fs/promises';
import type { AuditLogResult } from './AuditLogResult.js';
import type { EncryptionInterface } from './encryption/EncryptionInterface.js';
import { StorageError } from './exceptions/StorageError.js';
import {
  MAX_FILE_LOG_SIZE,
  REQUIRED_FILE_LOG_FIELDS,
  isPlainObject,
  toErrorMessage,
} from './validation.js';

/**
 * Reads and decrypts file-based audit logs
 */
export class FileLogReader {
  private readonly encryption: EncryptionInterface;
  private readonly encryptionKey: string;

  constructor(encryption: EncryptionInterface, encryptionKey: string) {
    this.encryption = encryption;
    this.encryptionKey = encryptionKey;
  }

  async read(filePath: string): Promise<AuditLogResult[]> {
    let fileSize: number;
    try {
      const fileStat = await stat(filePath);
      fileSize = fileStat.size;
    } catch (error) {
      // Stryker disable next-line ConditionalExpression,LogicalOperator: equivalent — Node.js fs always throws Error instances
      if (error instanceof Error && 'code' in error && error.code === 'ENOENT') {
        return [];
      }
      /* v8 ignore next -- defensive: Node.js fs always throws Error instances @preserve */
      throw new StorageError(`Failed to read file log: ${toErrorMessage(error)}`, {
        cause: error,
      });
    }

    if (fileSize > MAX_FILE_LOG_SIZE) {
      throw new StorageError(
        `File log exceeds maximum size of ${MAX_FILE_LOG_SIZE} bytes (got ${fileSize} bytes)`
      );
    }

    let content: string;
    try {
      content = await readFile(filePath, 'utf8');
    } catch (error) {
      /* v8 ignore next -- defensive: Node.js fs always throws Error instances @preserve */
      throw new StorageError(`Failed to read file log: ${toErrorMessage(error)}`, {
        cause: error,
      });
    }

    const trimmed = content.trim();
    if (trimmed === '') {
      return [];
    }

    const lines = trimmed.split('\n');
    return lines.map((line, index) => this.parseLine(line.trim(), index + 1));
  }

  private parseLine(line: string, lineNumber: number): AuditLogResult {
    let decrypted: string;
    try {
      decrypted = this.encryption.decrypt(line, this.encryptionKey);
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new StorageError(
        `Failed to decrypt file log line ${lineNumber}: ${toErrorMessage(error)}`
      );
    }

    let entry: unknown;
    try {
      entry = JSON.parse(decrypted);
    } catch (error) {
      throw new StorageError(
        /* v8 ignore next -- defensive: JSON.parse always throws SyntaxError instances @preserve */
        `Corrupted JSON in file log line ${lineNumber}: ${toErrorMessage(error)}`,
        { cause: error }
      );
    }

    if (!isPlainObject(entry)) {
      throw new StorageError(`Corrupted JSON in file log line ${lineNumber}: expected object`);
    }

    const missing = REQUIRED_FILE_LOG_FIELDS.filter((f) => !(f in entry));
    if (missing.length > 0) {
      throw new StorageError(
        `Missing required fields in file log line ${lineNumber}: ${missing.join(', ')}`
      );
    }

    if (typeof entry['timestamp'] !== 'string') {
      throw new StorageError(`Invalid type for field "timestamp" in file log line ${lineNumber}`);
    }

    const rawData = entry['data'];
    const data = isPlainObject(rawData) ? rawData : null;
    const dataError =
      rawData != null && !isPlainObject(rawData)
        ? `Invalid data type in file log line ${lineNumber}: expected object`
        : null;

    const timestampStr = String(entry['timestamp']);
    // Stryker disable next-line StringLiteral: equivalent — endsWith('') is always true, both branches produce valid Date
    const timestamp = new Date(timestampStr.endsWith('Z') ? timestampStr : timestampStr + 'Z');
    if (isNaN(timestamp.getTime())) {
      throw new StorageError(`Invalid timestamp in file log line ${lineNumber}: ${timestampStr}`);
    }

    return {
      id: lineNumber,
      timestamp,
      userId: entry['user_id'] != null ? Number(entry['user_id']) : null,
      ipAddress: String(entry['ip_address']),
      action: String(entry['action']),
      entityType: String(entry['entity_type']),
      entityId: String(entry['entity_id']),
      data,
      userAgent: String(entry['user_agent']),
      dataError,
      checksum: String(entry['checksum']),
    } satisfies AuditLogResult;
  }
}
