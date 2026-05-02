import { constants } from 'node:fs';
import { type FileHandle, appendFile, mkdir, open, stat, unlink } from 'node:fs/promises';
import { dirname } from 'node:path';
import type { AuditLogEntry } from './AuditLogEntry.js';
import type { EncryptionInterface } from './encryption/EncryptionInterface.js';
import { StorageError } from './exceptions/StorageError.js';
import { MAX_FILE_LOG_SIZE, toErrorMessage } from './validation.js';

export class FileLogWriter {
  private static readonly LOCK_STALE_MS = 60_000;

  private readonly fileEncryption: EncryptionInterface;
  private readonly encryptionKey: string;
  private readonly logFilePath: string;

  constructor(fileEncryption: EncryptionInterface, encryptionKey: string, logFilePath: string) {
    this.fileEncryption = fileEncryption;
    this.encryptionKey = encryptionKey;
    this.logFilePath = logFilePath;
  }

  async write(timestamp: string, entry: AuditLogEntry, checksum: string): Promise<void> {
    await mkdir(dirname(this.logFilePath), { recursive: true, mode: 0o700 });

    try {
      const fileStat = await stat(this.logFilePath);
      if (fileStat.size >= MAX_FILE_LOG_SIZE) {
        throw new StorageError(
          `File log has reached maximum size (${MAX_FILE_LOG_SIZE} bytes). Configure external log rotation.`
        );
      }
    } catch (error) {
      if (error instanceof StorageError) {
        throw error;
      }
      // File does not exist yet — proceed with writing
    }

    let payload: string;
    // Stryker disable BlockStatement,StringLiteral,ObjectLiteral: unreachable catch — encodeData() catches JSON serialization errors first
    try {
      payload = JSON.stringify({
        timestamp,
        user_id: entry.userId,
        ip_address: entry.ipAddress,
        user_agent: entry.userAgent,
        action: entry.action,
        entity_type: entry.entityType,
        entity_id: String(entry.entityId),
        data: entry.data,
        checksum,
      });
      /* v8 ignore start -- defensive: JSON.stringify only throws for circular refs or BigInt @preserve */
    } catch (error) {
      throw new StorageError(`Failed to encode file log entry as JSON: ${toErrorMessage(error)}`, {
        cause: error,
      });
    }
    /* v8 ignore stop -- @preserve */
    // Stryker restore BlockStatement,StringLiteral,ObjectLiteral

    const encrypted = this.fileEncryption.encrypt(payload, this.encryptionKey);
    await this.writeWithLock(encrypted + '\n');
  }

  private async writeWithLock(content: string): Promise<void> {
    const lockPath = `${this.logFilePath}.lock`;
    await this.removeStaleLock(lockPath);
    let lockHandle: FileHandle | undefined;
    try {
      lockHandle = await open(lockPath, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY);
      await appendFile(this.logFilePath, content, { mode: 0o600 });
    } finally {
      if (lockHandle) {
        await lockHandle.close();
        try {
          await unlink(lockPath);
        } catch {
          // Best-effort cleanup — lock file may already be gone
        }
      }
    }
  }

  private async removeStaleLock(lockPath: string): Promise<void> {
    try {
      const lockStat = await stat(lockPath);
      if (Date.now() - lockStat.mtimeMs >= FileLogWriter.LOCK_STALE_MS) {
        try {
          await unlink(lockPath);
        } catch {
          // Best-effort cleanup — lock file may already be gone
        }
      }
    } catch {
      // Lock file does not exist — nothing to clean up
    }
  }
}
