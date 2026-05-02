import type { AuditLogResult } from './AuditLogResult.js';
import type { EncryptionInterface } from './encryption/EncryptionInterface.js';
import { StorageError } from './exceptions/StorageError.js';
import {
  DEFAULT_USER_AGENT,
  REQUIRED_DB_ROW_FIELDS,
  isPlainObject,
  toErrorMessage,
} from './validation.js';

export interface ResultMapperContext {
  readonly useDbEncryption: boolean;
  readonly encryption: EncryptionInterface;
  readonly encryptionKey: string;
}

export class ResultMapper {
  static mapAll(rows: Record<string, unknown>[], context: ResultMapperContext): AuditLogResult[] {
    return rows.map((row) => ResultMapper.map(row, context));
  }

  static map(row: Record<string, unknown>, context: ResultMapperContext): AuditLogResult {
    ResultMapper.validateRowSchema(row);

    const dataField = context.useDbEncryption ? 'data_decrypted' : 'data';
    if (!(dataField in row)) {
      throw new StorageError(`Missing required field "${dataField}" in database row`);
    }

    const dataString =
      typeof row[dataField] === 'string'
        ? context.useDbEncryption
          ? row[dataField]
          : context.encryption.decrypt(row[dataField], context.encryptionKey)
        : null;

    const { data, userAgent, dataError } = ResultMapper.parseEnvelopeString(dataString);

    const timestamp = new Date(String(row['timestamp']));
    if (isNaN(timestamp.getTime())) {
      throw new StorageError(`Invalid timestamp in audit log: ${String(row['timestamp'])}`);
    }

    return {
      id: Number(row['id']),
      timestamp,
      userId:
        row['user_id'] !== null && row['user_id'] !== undefined ? Number(row['user_id']) : null,
      ipAddress: String(row['ip_address']),
      action: String(row['action']),
      entityType: String(row['entity_type']),
      entityId: String(row['entity_id']),
      data,
      userAgent,
      dataError,
      checksum: String(row['checksum']),
    } satisfies AuditLogResult;
  }

  private static validateRowSchema(row: Record<string, unknown>): void {
    const missing = REQUIRED_DB_ROW_FIELDS.filter((field) => !(field in row));
    if (missing.length > 0) {
      throw new StorageError(`Missing required fields in database row: ${missing.join(', ')}`);
    }

    const numberOrStringFields = ['id', 'entity_id'] as const;
    for (const field of numberOrStringFields) {
      if (typeof row[field] !== 'number' && typeof row[field] !== 'string') {
        throw new StorageError(`Invalid type for field "${field}" in database row`);
      }
    }

    if (typeof row['timestamp'] !== 'string' && !(row['timestamp'] instanceof Date)) {
      throw new StorageError('Invalid type for field "timestamp" in database row');
    }

    if (
      row['user_id'] != null &&
      typeof row['user_id'] !== 'number' &&
      typeof row['user_id'] !== 'string'
    ) {
      throw new StorageError('Invalid type for field "user_id" in database row');
    }

    const stringFields = ['ip_address', 'action', 'entity_type'] as const;
    for (const field of stringFields) {
      if (typeof row[field] !== 'string') {
        throw new StorageError(`Invalid type for field "${field}" in database row`);
      }
    }

    if (typeof row['checksum'] !== 'string' || !/^[a-f0-9]{64}$/.test(row['checksum'])) {
      throw new StorageError('Invalid type for field "checksum" in database row');
    }
  }

  private static parseEnvelopeString(dataString: string | null): {
    data: Record<string, unknown> | null;
    userAgent: string;
    dataError: string | null;
  } {
    // Stryker disable next-line ConditionalExpression: equivalent — JSON.parse(null) → null → same path
    if (dataString === null || dataString === '') {
      return { data: null, userAgent: DEFAULT_USER_AGENT, dataError: null };
    }

    try {
      const decoded: unknown = JSON.parse(dataString);
      if (isPlainObject(decoded)) {
        return ResultMapper.extractEnvelope(decoded);
      }
    } catch (error) {
      return {
        data: null,
        userAgent: DEFAULT_USER_AGENT,
        /* v8 ignore next -- defensive: JSON.parse always throws Error instances @preserve */
        dataError: `Corrupted JSON data: ${toErrorMessage(error)}`,
      };
    }

    return { data: null, userAgent: DEFAULT_USER_AGENT, dataError: null };
  }

  private static extractEnvelope(envelope: Record<string, unknown>): {
    data: Record<string, unknown> | null;
    userAgent: string;
    dataError: string | null;
  } {
    const meta = envelope['meta'];
    const userAgent =
      isPlainObject(meta) && typeof meta['user_agent'] === 'string'
        ? meta['user_agent']
        : DEFAULT_USER_AGENT;

    const innerData = envelope['data'];
    const data = isPlainObject(innerData) ? innerData : null;

    return { data, userAgent, dataError: null };
  }
}
