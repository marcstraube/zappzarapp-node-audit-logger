import { AuditLogError } from './exceptions/AuditLogError.js';

/**
 * Immutable audit log entry with input validation
 */
export class AuditLogEntry {
  private static readonly MAX_ACTION_LENGTH = 255;
  private static readonly MAX_ENTITY_TYPE_LENGTH = 100;
  private static readonly MAX_ENTITY_ID_LENGTH = 255;
  private static readonly MAX_IP_ADDRESS_LENGTH = 45;
  private static readonly MAX_USER_AGENT_LENGTH = 500;

  readonly action: string;
  readonly entityType: string;
  readonly entityId: string | number;
  readonly userId: number | null;
  readonly ipAddress: string;
  readonly userAgent: string;
  readonly data: Readonly<Record<string, unknown>>;

  constructor(params: {
    action: string;
    entityType: string;
    entityId: string | number;
    userId?: number | null;
    ipAddress?: string;
    userAgent?: string;
    data?: Readonly<Record<string, unknown>>;
  }) {
    this.validateNotEmpty(params.action, 'Action');
    this.validateMaxLength(params.action, 'Action', AuditLogEntry.MAX_ACTION_LENGTH);
    this.validateNotEmpty(params.entityType, 'Entity type');
    this.validateMaxLength(params.entityType, 'Entity type', AuditLogEntry.MAX_ENTITY_TYPE_LENGTH);
    this.validateNotEmpty(String(params.entityId), 'Entity ID');
    this.validateMaxLength(
      String(params.entityId),
      'Entity ID',
      AuditLogEntry.MAX_ENTITY_ID_LENGTH
    );

    this.action = params.action;
    this.entityType = params.entityType;
    this.entityId = params.entityId;
    this.userId = params.userId ?? null;
    this.ipAddress = params.ipAddress ?? 'unknown';
    this.userAgent = params.userAgent ?? 'unknown';
    this.data = params.data !== undefined ? structuredClone(params.data) : {};

    this.validateMaxLength(this.ipAddress, 'IP address', AuditLogEntry.MAX_IP_ADDRESS_LENGTH);
    this.validateMaxLength(this.userAgent, 'User agent', AuditLogEntry.MAX_USER_AGENT_LENGTH);

    Object.freeze(this);
  }

  private validateNotEmpty(value: string, field: string): void {
    if (value === '') {
      throw new AuditLogError(`${field} must not be empty`);
    }
  }

  private validateMaxLength(value: string, field: string, max: number): void {
    if (Buffer.byteLength(value) > max) {
      throw new AuditLogError(`${field} must not exceed ${max} bytes`);
    }
  }
}
