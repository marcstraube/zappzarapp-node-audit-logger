import type { AuditLogEntry } from './AuditLogEntry.js';
import type { AuditLogResult } from './AuditLogResult.js';
import type { AuditLoggerInterface } from './AuditLoggerInterface.js';

/**
 * Null Object Audit Logger - No-op implementation
 *
 * Use for environments where audit logging is not required.
 * Implements AuditLoggerInterface but performs no operations.
 */
export class NullAuditLogger implements AuditLoggerInterface {
  log(_entry: AuditLogEntry): Promise<void> {
    return Promise.resolve();
  }

  logAuth(
    _action: string,
    _userId?: number | null,
    _data?: Readonly<Record<string, unknown>>,
    _ipAddress?: string,
    _userAgent?: string
  ): Promise<void> {
    return Promise.resolve();
  }

  logAdmin(
    _action: string,
    _adminUserId: number,
    _entityType: string,
    _entityId: string | number,
    _data?: Readonly<Record<string, unknown>>,
    _ipAddress?: string,
    _userAgent?: string
  ): Promise<void> {
    return Promise.resolve();
  }

  getLogsForEntity(
    _entityType: string,
    _entityId: string | number,
    _limit?: number
  ): Promise<AuditLogResult[]> {
    return Promise.resolve([]);
  }

  getLogsForUser(_userId: number, _limit?: number): Promise<AuditLogResult[]> {
    return Promise.resolve([]);
  }

  readFileLog(): Promise<AuditLogResult[]> {
    return Promise.resolve([]);
  }

  verify(_result: AuditLogResult): boolean {
    return false;
  }
}
