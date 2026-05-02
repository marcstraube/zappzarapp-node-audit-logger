import { createHmac, hkdfSync, timingSafeEqual } from 'node:crypto';
import type { AuditLogEntry } from './AuditLogEntry.js';
import type { AuditLogResult } from './AuditLogResult.js';
import { StorageError } from './exceptions/StorageError.js';
import { HKDF_SALT, toErrorMessage } from './validation.js';

export class ChecksumCalculator {
  static readonly HMAC_HKDF_INFO = 'audit-logger-hmac' as const;
  static readonly MAX_ENCODED_DATA_SIZE = 10_000;

  private readonly hmacKey: Buffer;

  constructor(hmacKey: Buffer) {
    this.hmacKey = hmacKey;
  }

  static deriveKey(encryptionKey: string): Buffer {
    return Buffer.from(
      hkdfSync('sha256', encryptionKey, HKDF_SALT, ChecksumCalculator.HMAC_HKDF_INFO, 32)
    );
  }

  // Stryker disable Regex: equivalent — toISOString() always has exactly one .dddZ
  formatTimestamp(date: Date): string {
    return date
      .toISOString()
      .replace('T', ' ')
      .replace(/\.\d+Z$/, '');
  }
  // Stryker restore Regex

  buildEnvelope(
    userAgent: string,
    timestamp: string,
    data: Readonly<Record<string, unknown>> | null
  ): {
    meta: { user_agent: string; timestamp: string };
    data: Readonly<Record<string, unknown>> | null;
  } {
    return { meta: { user_agent: userAgent, timestamp }, data };
  }

  encodeData(entry: AuditLogEntry, timestamp: string): string {
    const envelope = this.buildEnvelope(entry.userAgent, timestamp, { ...entry.data });

    let dataJson: string;
    try {
      dataJson = JSON.stringify(envelope);
    } catch (error) {
      /* v8 ignore next -- defensive: JSON.stringify always throws Error instances @preserve */
      throw new StorageError(`Failed to encode audit data as JSON: ${toErrorMessage(error)}`, {
        cause: error,
      });
    }

    const dataSize = Buffer.byteLength(dataJson);
    if (dataSize > ChecksumCalculator.MAX_ENCODED_DATA_SIZE) {
      throw new StorageError(
        `Encoded data size exceeds maximum of ${ChecksumCalculator.MAX_ENCODED_DATA_SIZE} bytes (got ${dataSize} bytes)`
      );
    }

    return dataJson;
  }

  calculate(params: {
    timestamp: string;
    userId: number | null;
    ipAddress: string;
    action: string;
    entityType: string;
    entityId: string;
    dataJson: string;
  }): string {
    const input = [
      params.timestamp,
      params.userId !== null ? String(params.userId) : '',
      params.ipAddress,
      params.action,
      params.entityType,
      params.entityId,
      params.dataJson,
    ].join('\0');
    return createHmac('sha256', this.hmacKey).update(input).digest('hex');
  }

  verify(result: AuditLogResult): boolean {
    if (result.dataError !== null) {
      return false;
    }

    const timestamp = this.formatTimestamp(result.timestamp);

    // Stryker disable BlockStatement: equivalent — undefined dataJson → checksum mismatch → false
    let dataJson: string;
    try {
      dataJson = JSON.stringify(this.buildEnvelope(result.userAgent, timestamp, result.data));
    } catch {
      return false;
    }
    // Stryker restore BlockStatement

    const expected = this.calculate({
      timestamp,
      userId: result.userId,
      ipAddress: result.ipAddress,
      action: result.action,
      entityType: result.entityType,
      entityId: result.entityId,
      dataJson,
    });

    const expectedBuf = Buffer.from(expected, 'hex');
    const checksumBuf = Buffer.from(result.checksum, 'hex');

    if (expectedBuf.length !== checksumBuf.length) {
      return false;
    }

    return timingSafeEqual(expectedBuf, checksumBuf);
  }
}
