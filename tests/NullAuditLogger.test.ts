import { describe, it, expect, beforeEach } from 'vitest';
import { AuditLogEntry } from '../src/AuditLogEntry.js';
import { NullAuditLogger } from '../src/NullAuditLogger.js';
import type { AuditLogResult } from '../src/AuditLogResult.js';

describe('NullAuditLogger', () => {
  let logger: NullAuditLogger;

  beforeEach(() => {
    logger = new NullAuditLogger();
  });

  it('should not throw on log()', async () => {
    const entry = new AuditLogEntry({
      action: 'user.view',
      entityType: 'user',
      entityId: 123,
      userId: 1,
      ipAddress: '127.0.0.1',
      userAgent: 'Vitest',
      data: { field: 'value' },
    });

    await expect(logger.log(entry)).resolves.toBeUndefined();
  });

  it('should not throw on logAuth()', async () => {
    await expect(
      logger.logAuth('auth.login', 1, { method: '2fa' }, '127.0.0.1', 'Vitest')
    ).resolves.toBeUndefined();
  });

  it('should not throw on logAuth() with null userId', async () => {
    await expect(
      logger.logAuth('auth.failed', null, { reason: 'invalid_password' }, '127.0.0.1', 'Vitest')
    ).resolves.toBeUndefined();
  });

  it('should not throw on logAdmin()', async () => {
    await expect(
      logger.logAdmin(
        'admin.user.update',
        1,
        'user',
        123,
        { field: 'updated' },
        '127.0.0.1',
        'Vitest'
      )
    ).resolves.toBeUndefined();
  });

  it('should not throw on logAdmin() with string entityId', async () => {
    await expect(
      logger.logAdmin(
        'admin.document.delete',
        1,
        'document',
        'doc-uuid-123',
        {},
        '127.0.0.1',
        'Vitest'
      )
    ).resolves.toBeUndefined();
  });

  it('should return empty array from getLogsForEntity()', async () => {
    const result = await logger.getLogsForEntity('user', 123, 50);

    expect(result).toEqual([]);
  });

  it('should return empty array from getLogsForEntity() with string id', async () => {
    const result = await logger.getLogsForEntity('document', 'doc-123', 100);

    expect(result).toEqual([]);
  });

  it('should return empty array from getLogsForUser()', async () => {
    const result = await logger.getLogsForUser(1, 50);

    expect(result).toEqual([]);
  });

  it('should return false from verify()', () => {
    const result: AuditLogResult = {
      id: 1,
      timestamp: new Date(),
      userId: 1,
      ipAddress: '127.0.0.1',
      action: 'user.view',
      entityType: 'user',
      entityId: '123',
      data: { field: 'value' },
      userAgent: 'Vitest',
      dataError: null,
      checksum: 'a'.repeat(64),
    };

    expect(logger.verify(result)).toBe(false);
  });

  it('should return false from verify() with null userId', () => {
    const result: AuditLogResult = {
      id: 1,
      timestamp: new Date(),
      userId: null,
      ipAddress: '127.0.0.1',
      action: 'system.cleanup',
      entityType: 'system',
      entityId: '1',
      data: null,
      userAgent: 'unknown',
      dataError: null,
      checksum: 'a'.repeat(64),
    };

    expect(logger.verify(result)).toBe(false);
  });

  it('should return empty array from readFileLog()', async () => {
    const result = await logger.readFileLog();

    expect(result).toEqual([]);
  });

  it('should handle multiple operations without interference', async () => {
    const entry = new AuditLogEntry({
      action: 'test.action',
      entityType: 'test',
      entityId: 1,
    });

    await logger.log(entry);
    await logger.logAuth('auth.test', 1);
    await logger.logAdmin('admin.test', 1, 'test', 1);

    const logsForEntity = await logger.getLogsForEntity('test', 1);
    const logsForUser = await logger.getLogsForUser(1);
    const fileLog = await logger.readFileLog();

    expect(logsForEntity).toEqual([]);
    expect(logsForUser).toEqual([]);
    expect(fileLog).toEqual([]);
  });
});
