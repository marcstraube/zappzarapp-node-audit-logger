import type { AuditLogEntry } from './AuditLogEntry.js';
import type { AuditLogResult } from './AuditLogResult.js';

/**
 * Audit Logger Interface for GDPR-compliant audit logging
 *
 * GDPR Art. 30: Records of processing activities
 * GDPR Art. 32: Security measures (logging access to personal data)
 */
export interface AuditLoggerInterface {
  /**
   * Log an audit event
   *
   * @throws AuditLogError
   */
  log(entry: AuditLogEntry): Promise<void>;

  /**
   * Log authentication event
   *
   * @param action - Action performed (e.g., 'login.success', 'login.failed')
   * @param userId - User ID (null for failed login attempts)
   * @param data - Additional data
   * @param ipAddress - Client IP address
   * @param userAgent - Client user agent
   *
   * @throws AuditLogError
   */
  logAuth(
    action: string,
    userId?: number | null,
    data?: Readonly<Record<string, unknown>>,
    ipAddress?: string,
    userAgent?: string
  ): Promise<void>;

  /**
   * Log administrative action
   *
   * @param action - Action performed (e.g., 'role.granted')
   * @param adminUserId - Administrator who performed the action
   * @param entityType - Entity type affected
   * @param entityId - Entity ID affected
   * @param data - Additional data
   * @param ipAddress - Client IP address
   * @param userAgent - Client user agent
   *
   * @throws AuditLogError
   */
  logAdmin(
    action: string,
    adminUserId: number,
    entityType: string,
    entityId: string | number,
    data?: Readonly<Record<string, unknown>>,
    ipAddress?: string,
    userAgent?: string
  ): Promise<void>;

  /**
   * Retrieve audit logs for a specific entity
   *
   * @throws AuditLogError
   */
  getLogsForEntity(
    entityType: string,
    entityId: string | number,
    limit?: number
  ): Promise<AuditLogResult[]>;

  /**
   * Retrieve audit logs for a specific user
   *
   * @throws AuditLogError
   */
  getLogsForUser(userId: number, limit?: number): Promise<AuditLogResult[]>;

  /**
   * Read and decrypt the file log
   *
   * @throws AuditLogError
   */
  readFileLog(): Promise<AuditLogResult[]>;

  /**
   * Verify the integrity of an audit log entry by recalculating its HMAC checksum.
   * Returns false immediately if `result.dataError` is set.
   * Accepts `null` data — the checksum is computed over the JSON-serialized envelope,
   * which uses `null` as the data value when no data is present.
   */
  verify(result: AuditLogResult): boolean;
}
