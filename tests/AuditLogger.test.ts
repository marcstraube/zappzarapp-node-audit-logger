// noinspection ES6RedundantAwait

import { createHmac, hkdfSync } from 'node:crypto';
import {
  closeSync,
  existsSync,
  ftruncateSync,
  openSync,
  readFileSync,
  rmdirSync,
  statSync,
  unlinkSync,
  utimesSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AuditLogEntry } from '../src/AuditLogEntry.js';
import { AuditLogger } from '../src/AuditLogger.js';
import type { AuditLogResult } from '../src/AuditLogResult.js';
import type { QueryExecutor } from '../src/QueryExecutor.js';
import { AppEncryption } from '../src/encryption/AppEncryption.js';
import { DatabaseEncryption } from '../src/encryption/DatabaseEncryption.js';
import type { EncryptionInterface } from '../src/encryption/EncryptionInterface.js';
import { AuditLogError } from '../src/exceptions/AuditLogError.js';
import { StorageError } from '../src/exceptions/StorageError.js';

function createMockExecutor(): QueryExecutor {
  return {
    query: vi.fn().mockResolvedValue([]) as QueryExecutor['query'],
    execute: vi.fn().mockResolvedValue({ affectedRows: 1 }) as QueryExecutor['execute'],
  };
}

const encryptionKey = 'test-encryption-key-32-characters!';
const hmacKey = Buffer.from(
  hkdfSync('sha256', encryptionKey, 'zappzarapp-audit-logger', 'audit-logger-hmac', 32)
);

function computeTestChecksum(
  timestamp: string,
  userId: number | null,
  ipAddress: string,
  action: string,
  entityType: string,
  entityId: string,
  dataJson: string
): string {
  const input = [
    timestamp,
    userId !== null ? String(userId) : '',
    ipAddress,
    action,
    entityType,
    entityId,
    dataJson,
  ].join('\0');
  return createHmac('sha256', hmacKey).update(input).digest('hex');
}

describe('AuditLogger', () => {
  let tempLogFile: string;

  beforeEach(() => {
    tempLogFile = join(
      tmpdir(),
      `audit-test-${Date.now()}-${Math.random().toString(36).slice(2)}.log`
    );
  });

  afterEach(() => {
    if (existsSync(tempLogFile)) {
      unlinkSync(tempLogFile);
    }
    const lockFile = `${tempLogFile}.lock`;
    if (existsSync(lockFile)) {
      unlinkSync(lockFile);
    }
  });

  describe('constructor', () => {
    it('should throw if encryption key is shorter than 32 bytes', () => {
      const executor = createMockExecutor();
      expect(() => new AuditLogger(executor, 'short-key', 'postgres')).toThrow(
        'Encryption key must be at least 32 bytes'
      );
    });

    it('should accept a key of exactly 32 bytes', () => {
      const executor = createMockExecutor();
      expect(() => new AuditLogger(executor, 'a'.repeat(32), 'postgres')).not.toThrow();
    });

    it('should validate byte length not character count for encryption key', () => {
      const executor = createMockExecutor();
      // 20 * 'ä' = 40 bytes in UTF-8, but only 20 characters — should pass
      expect(() => new AuditLogger(executor, 'ä'.repeat(20), 'postgres')).not.toThrow();
      // 15 * 'ä' = 30 bytes in UTF-8, but only 15 characters — should fail
      expect(() => new AuditLogger(executor, 'ä'.repeat(15), 'postgres')).toThrow(
        'Encryption key must be at least 32 bytes'
      );
    });

    it('should throw if maxLimit is less than 1', () => {
      const executor = createMockExecutor();
      expect(() => new AuditLogger(executor, encryptionKey, 'postgres', { maxLimit: 0 })).toThrow(
        'maxLimit must be at least 1'
      );
    });

    it('should accept maxLimit of 1', () => {
      const executor = createMockExecutor();
      expect(
        () => new AuditLogger(executor, encryptionKey, 'postgres', { maxLimit: 1 })
      ).not.toThrow();
    });

    it('should accept valid maxLimit', () => {
      const executor = createMockExecutor();
      expect(
        () => new AuditLogger(executor, encryptionKey, 'postgres', { maxLimit: 500 })
      ).not.toThrow();
    });

    it('should accept undefined maxLimit', () => {
      const executor = createMockExecutor();
      expect(() => new AuditLogger(executor, encryptionKey, 'postgres')).not.toThrow();
    });

    it('should reject negative maxLimit', () => {
      const executor = createMockExecutor();
      expect(() => new AuditLogger(executor, encryptionKey, 'postgres', { maxLimit: -1 })).toThrow(
        'maxLimit must be at least 1'
      );
    });
  });

  describe('log()', () => {
    it('should write to database with app encryption (postgres)', async () => {
      const mockEncryption: EncryptionInterface = {
        encrypt: vi.fn().mockReturnValue('encrypted-data'),
        decrypt: vi.fn(),
      };

      const executor = createMockExecutor();

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: mockEncryption,
      });

      await logger.log(
        new AuditLogEntry({
          action: 'user.login',
          entityType: 'user',
          entityId: 42,
          userId: 42,
          ipAddress: '127.0.0.1',
          userAgent: 'Vitest/1.0',
          data: { status: 'success' },
        })
      );

      expect(executor.execute).toHaveBeenCalledOnce();
      const [sql] = vi.mocked(executor.execute).mock.calls[0]!;
      expect(sql).toContain('INSERT INTO audit_logs');
      expect(sql).not.toContain('encrypt_text');
      expect(mockEncryption.encrypt).toHaveBeenCalledOnce();
    });

    it('should not use encrypt_text SQL function with app encryption', async () => {
      const mockEncryption: EncryptionInterface = {
        encrypt: vi.fn().mockReturnValue('encrypted-data'),
        decrypt: vi.fn(),
      };

      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: mockEncryption,
      });

      await logger.log(
        new AuditLogEntry({
          action: 'user.login',
          entityType: 'user',
          entityId: 42,
        })
      );

      const [sql] = vi.mocked(executor.execute).mock.calls[0]!;
      expect(sql).toContain('INSERT INTO audit_logs');
      expect(sql).not.toContain('encrypt_text');
    });

    it('should use encrypt_text SQL function with database encryption (postgres)', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      await logger.log(
        new AuditLogEntry({
          action: 'user.login',
          entityType: 'user',
          entityId: 42,
        })
      );

      const [sql] = vi.mocked(executor.execute).mock.calls[0]!;
      expect(sql).toContain('encrypt_text');
    });

    it('should use $1, $2, ... placeholders for postgres dialect', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      await logger.log(
        new AuditLogEntry({
          action: 'test',
          entityType: 'test',
          entityId: 1,
        })
      );

      const [sql] = vi.mocked(executor.execute).mock.calls[0]!;
      expect(sql).toContain('$1');
      expect(sql).not.toContain('?');
    });

    it('should use ? placeholders for mysql dialect', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'mysql', {
        encryption: new DatabaseEncryption(),
      });

      await logger.log(
        new AuditLogEntry({
          action: 'test',
          entityType: 'test',
          entityId: 1,
        })
      );

      const [sql] = vi.mocked(executor.execute).mock.calls[0]!;
      expect(sql).toContain('?');
      expect(sql).not.toContain('$1');
    });

    it('should handle non-Error rejection from executor', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.execute).mockRejectedValue('raw string error');

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      await expect(
        logger.log(new AuditLogEntry({ action: 'test', entityType: 'test', entityId: 1 }))
      ).rejects.toThrow(StorageError);

      await expect(
        logger.log(new AuditLogEntry({ action: 'test', entityType: 'test', entityId: 1 }))
      ).rejects.toThrow('raw string error');
    });

    it('should write to file as fallback on database error and throw StorageError', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.execute).mockRejectedValue(new Error('Database connection failed'));

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
        logFilePath: tempLogFile,
      });

      await expect(
        logger.log(
          new AuditLogEntry({
            action: 'user.login',
            entityType: 'user',
            entityId: 42,
            userId: 42,
            ipAddress: '127.0.0.1',
          })
        )
      ).rejects.toThrow(StorageError);

      await expect(
        logger.log(
          new AuditLogEntry({
            action: 'user.login',
            entityType: 'user',
            entityId: 42,
          })
        )
      ).rejects.toThrow('Failed to write audit log to database');

      // File was written as fallback (encrypted)
      expect(existsSync(tempLogFile)).toBe(true);
      const content = readFileSync(tempLogFile, 'utf8');
      expect(content.trim().length).toBeGreaterThan(0);
    });

    it('should write encrypted file log for redundancy when logFilePath is set', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
        logFilePath: tempLogFile,
      });

      await logger.log(
        new AuditLogEntry({
          action: 'user.logout',
          entityType: 'user',
          entityId: 99,
          userId: 99,
          ipAddress: '192.168.1.1',
          userAgent: 'TestAgent/1.0',
          data: { reason: 'manual' },
        })
      );

      expect(existsSync(tempLogFile)).toBe(true);
      const content = readFileSync(tempLogFile, 'utf8');
      const lines = content.trim().split('\n');
      expect(lines).toHaveLength(1);

      // File content is encrypted, so we can't parse it directly as JSON
      // But we can decrypt it and check
      const appEncryption = new AppEncryption();
      const decrypted = appEncryption.decrypt(lines[0]!, encryptionKey);
      const logEntry = JSON.parse(decrypted) as Record<string, unknown>;

      expect(logEntry['action']).toBe('user.logout');
      expect(logEntry['entity_type']).toBe('user');
      expect(logEntry['entity_id']).toBe('99');
      expect(logEntry['user_id']).toBe(99);
      expect(logEntry['ip_address']).toBe('192.168.1.1');
      expect(logEntry['checksum']).toBeDefined();
    });

    it('should not write file when logFilePath is null', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
        logFilePath: null,
      });

      await logger.log(
        new AuditLogEntry({
          action: 'user.login',
          entityType: 'user',
          entityId: 1,
        })
      );

      expect(existsSync(tempLogFile)).toBe(false);
    });

    it('should write encrypted JSON lines format for multiple entries', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
        logFilePath: tempLogFile,
      });

      await logger.log(new AuditLogEntry({ action: 'action1', entityType: 'type1', entityId: 1 }));
      await logger.log(new AuditLogEntry({ action: 'action2', entityType: 'type2', entityId: 2 }));

      const content = readFileSync(tempLogFile, 'utf8');
      const lines = content.trim().split('\n');

      expect(lines).toHaveLength(2);

      const appEncryption = new AppEncryption();
      const entry1 = JSON.parse(appEncryption.decrypt(lines[0]!, encryptionKey)) as Record<
        string,
        unknown
      >;
      expect(entry1['action']).toBe('action1');

      const entry2 = JSON.parse(appEncryption.decrypt(lines[1]!, encryptionKey)) as Record<
        string,
        unknown
      >;
      expect(entry2['action']).toBe('action2');
    });

    it('should use meta/data envelope structure', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      await logger.log(
        new AuditLogEntry({
          action: 'user.login',
          entityType: 'user',
          entityId: 42,
          userAgent: 'Vitest/1.0',
          data: { status: 'success' },
        })
      );

      const [, params] = vi.mocked(executor.execute).mock.calls[0]!;
      // With DB encryption, the data JSON is passed directly
      const dataParam = params?.find(
        (p) => typeof p === 'string' && p.includes('"meta"')
      ) as string;
      expect(dataParam).toBeDefined();

      const envelope = JSON.parse(dataParam) as Record<string, unknown>;
      expect(envelope).toHaveProperty('meta');
      expect(envelope).toHaveProperty('data');
      const meta = envelope['meta'] as Record<string, unknown>;
      expect(meta['user_agent']).toBe('Vitest/1.0');
      const data = envelope['data'] as Record<string, unknown>;
      expect(data['status']).toBe('success');
    });

    it('should throw StorageError when encoded data exceeds max size', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      const largeData: Record<string, unknown> = {};
      for (let i = 0; i < 500; i++) {
        largeData[`key_${i}`] = 'x'.repeat(20);
      }

      await expect(
        logger.log(
          new AuditLogEntry({
            action: 'test',
            entityType: 'test',
            entityId: 1,
            data: largeData,
          })
        )
      ).rejects.toThrow(StorageError);

      await expect(
        logger.log(
          new AuditLogEntry({
            action: 'test',
            entityType: 'test',
            entityId: 1,
            data: largeData,
          })
        )
      ).rejects.toThrow('Encoded data size exceeds maximum');
    });

    it('should throw StorageError when data contains non-serializable value (BigInt)', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      await expect(
        logger.log(
          new AuditLogEntry({
            action: 'test',
            entityType: 'test',
            entityId: '1',
            data: { value: BigInt(42) } as unknown as Record<string, unknown>,
          })
        )
      ).rejects.toThrow(StorageError);

      await expect(
        logger.log(
          new AuditLogEntry({
            action: 'test',
            entityType: 'test',
            entityId: '1',
            data: { value: BigInt(42) } as unknown as Record<string, unknown>,
          })
        )
      ).rejects.toThrow('Failed to encode audit data as JSON');
    });

    it('should include combined error when both DB and file fail', async () => {
      const impossibleLogFile = '/dev/null/impossible/path/audit.log';

      const executor = createMockExecutor();
      vi.mocked(executor.execute).mockRejectedValue(new Error('DB down'));

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
        logFilePath: impossibleLogFile,
      });

      await expect(
        logger.log(new AuditLogEntry({ action: 'test', entityType: 'test', entityId: 1 }))
      ).rejects.toThrow('File fallback also failed');
    });

    it('should handle non-Error db failure message', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.execute).mockRejectedValue('raw db error');

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
        logFilePath: null,
      });

      await expect(
        logger.log(new AuditLogEntry({ action: 'test', entityType: 'test', entityId: 1 }))
      ).rejects.toThrow('raw db error');
    });
  });

  describe('logAuth()', () => {
    it('should create entry with entityType auth', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      await logger.logAuth('user.login', 42, { method: '2fa' }, '127.0.0.1', 'Mozilla/5.0');

      expect(executor.execute).toHaveBeenCalledOnce();
      const [, params] = vi.mocked(executor.execute).mock.calls[0]!;
      expect(params).toContain('auth');
      expect(params).toContain('user.login');
      expect(params).toContain('42');
    });

    it('should use 0 as entityId when userId is null', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      await logger.logAuth('login.failed', null);

      const [, params] = vi.mocked(executor.execute).mock.calls[0]!;
      expect(params).toContain('0');
      expect(params).toContain(null);
    });
  });

  describe('logAdmin()', () => {
    it('should include admin_user_id in data envelope', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      await logger.logAdmin(
        'user.delete',
        99,
        'user',
        42,
        { reason: 'violation' },
        '10.0.0.1',
        'AdminPanel/1.0'
      );

      expect(executor.execute).toHaveBeenCalledOnce();
      const [, params] = vi.mocked(executor.execute).mock.calls[0]!;

      const dataParam = params?.find((p) => typeof p === 'string' && p.includes('admin_user_id'));
      expect(dataParam).toBeDefined();
      const envelope = JSON.parse(dataParam as string) as Record<string, unknown>;
      const data = envelope['data'] as Record<string, unknown>;
      expect(data['admin_user_id']).toBe(99);
    });
  });

  describe('getLogsForEntity()', () => {
    it('should decrypt data and extract envelope with app encryption (postgres)', async () => {
      const appEncryption = new AppEncryption();
      const envelope = {
        meta: { user_agent: 'TestAgent/1.0', timestamp: '2026-02-13 12:00:00' },
        data: { test: 'data' },
      };
      const encrypted = appEncryption.encrypt(JSON.stringify(envelope), encryptionKey);

      const executor = createMockExecutor();
      vi.mocked(executor.query).mockResolvedValue([
        {
          id: 1,
          timestamp: '2026-02-13 12:00:00',
          user_id: 42,
          ip_address: '127.0.0.1',
          action: 'user.view',
          entity_type: 'user',
          entity_id: '42',
          data: encrypted,
          checksum: 'a'.repeat(64),
        },
      ]);

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: appEncryption,
      });

      const results = await logger.getLogsForEntity('user', 42);

      expect(results).toHaveLength(1);
      expect(results[0]!.id).toBe(1);
      expect(results[0]!.action).toBe('user.view');
      expect(results[0]!.entityType).toBe('user');
      expect(results[0]!.entityId).toBe('42');
      expect(results[0]!.data).toEqual({ test: 'data' });
      expect(results[0]!.userAgent).toBe('TestAgent/1.0');
      expect(results[0]!.dataError).toBeNull();

      const [sql] = vi.mocked(executor.query).mock.calls[0]!;
      expect(sql).not.toContain('decrypt_text');
    });

    it('should use decrypt_text SQL function with database encryption (postgres)', async () => {
      const envelope = {
        meta: { user_agent: 'Agent/1.0', timestamp: '2026-02-13 12:00:00' },
        data: { test: 'data' },
      };
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockResolvedValue([
        {
          id: 1,
          timestamp: '2026-02-13 12:00:00',
          user_id: 42,
          ip_address: '127.0.0.1',
          action: 'user.view',
          entity_type: 'user',
          entity_id: '42',
          data_decrypted: JSON.stringify(envelope),
          checksum: 'a'.repeat(64),
        },
      ]);

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      const results = await logger.getLogsForEntity('user', 42);

      expect(results).toHaveLength(1);
      expect(results[0]!.data).toEqual({ test: 'data' });
      expect(results[0]!.userAgent).toBe('Agent/1.0');

      const [sql] = vi.mocked(executor.query).mock.calls[0]!;
      expect(sql).toContain('decrypt_text');
    });

    it('should use ? placeholders for mysql dialect', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'mysql', {
        encryption: new DatabaseEncryption(),
      });

      await logger.getLogsForEntity('user', 42);

      const [sql] = vi.mocked(executor.query).mock.calls[0]!;
      expect(sql).toContain('?');
      expect(sql).not.toContain('$1');
    });

    it('should use $1 placeholders for postgres dialect', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      await logger.getLogsForEntity('user', 42);

      const [sql] = vi.mocked(executor.query).mock.calls[0]!;
      expect(sql).toContain('$1');
      expect(sql).not.toContain('?');
    });

    it('should throw on limit < 1', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres');

      await expect(logger.getLogsForEntity('user', 1, 0)).rejects.toThrow(
        'Limit must be at least 1'
      );
    });

    it('should reject negative limit', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres');

      await expect(logger.getLogsForEntity('user', 1, -5)).rejects.toThrow(
        'Limit must be at least 1'
      );
    });

    it('should throw when limit exceeds maxLimit', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', { maxLimit: 50 });

      await expect(logger.getLogsForEntity('user', 1, 51)).rejects.toThrow(
        'Limit must not exceed 50'
      );
    });

    it('should use default limit of 100', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      await logger.getLogsForEntity('user', 42);

      const [, params] = vi.mocked(executor.query).mock.calls[0]!;
      expect(params![params!.length - 1]).toBe(100);
    });

    it('should pass correct query parameters', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      await logger.getLogsForEntity('user', 42, 25);

      const [sql, params] = vi.mocked(executor.query).mock.calls[0]!;
      expect(sql).toContain('entity_type');
      expect(sql).toContain('entity_id');
      expect(params).toContain('user');
      expect(params).toContain('42');
      expect(params![params!.length - 1]).toBe(25);
    });
  });

  describe('getLogsForUser()', () => {
    it('should decrypt data and extract envelope with app encryption', async () => {
      const appEncryption = new AppEncryption();
      const envelope = {
        meta: { user_agent: 'Agent/2.0', timestamp: '2026-02-13 13:00:00' },
        data: { action_type: 'view' },
      };
      const encrypted = appEncryption.encrypt(JSON.stringify(envelope), encryptionKey);

      const executor = createMockExecutor();
      vi.mocked(executor.query).mockResolvedValue([
        {
          id: 2,
          timestamp: '2026-02-13 13:00:00',
          user_id: 99,
          ip_address: '192.168.1.1',
          action: 'profile.update',
          entity_type: 'profile',
          entity_id: '99',
          data: encrypted,
          checksum: 'a'.repeat(64),
        },
      ]);

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: appEncryption,
      });

      const results = await logger.getLogsForUser(99);

      expect(results).toHaveLength(1);
      expect(results[0]!.userId).toBe(99);
      expect(results[0]!.action).toBe('profile.update');
      expect(results[0]!.data).toEqual({ action_type: 'view' });
      expect(results[0]!.userAgent).toBe('Agent/2.0');

      const [sql] = vi.mocked(executor.query).mock.calls[0]!;
      expect(sql).not.toContain('decrypt_text');
    });

    it('should use decrypt_text with database encryption', async () => {
      const envelope = {
        meta: { user_agent: 'unknown', timestamp: '2026-02-13 14:00:00' },
        data: { action_type: 'delete' },
      };
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockResolvedValue([
        {
          id: 3,
          timestamp: '2026-02-13 14:00:00',
          user_id: 55,
          ip_address: '10.0.0.1',
          action: 'user.delete',
          entity_type: 'user',
          entity_id: '55',
          data_decrypted: JSON.stringify(envelope),
          checksum: 'a'.repeat(64),
        },
      ]);

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      const results = await logger.getLogsForUser(55);

      expect(results).toHaveLength(1);
      expect(results[0]!.data).toEqual({ action_type: 'delete' });

      const [sql] = vi.mocked(executor.query).mock.calls[0]!;
      expect(sql).toContain('decrypt_text');
    });

    it('should use ? placeholders for mysql dialect', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'mysql');

      await logger.getLogsForUser(1);

      const [sql] = vi.mocked(executor.query).mock.calls[0]!;
      expect(sql).toContain('?');
      expect(sql).not.toContain('$1');
    });

    it('should use decrypt_text with database encryption on mysql', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'mysql', {
        encryption: new DatabaseEncryption(),
      });

      await logger.getLogsForUser(1);

      const [sql] = vi.mocked(executor.query).mock.calls[0]!;
      expect(sql).toContain('decrypt_text');
      expect(sql).toContain('?');
      expect(sql).not.toContain('$1');
    });

    it('should throw on limit < 1', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres');

      await expect(logger.getLogsForUser(1, 0)).rejects.toThrow('Limit must be at least 1');
    });

    it('should reject negative limit', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres');

      await expect(logger.getLogsForUser(1, -10)).rejects.toThrow('Limit must be at least 1');
    });

    it('should reject limit exceeding maxLimit', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', { maxLimit: 50 });

      await expect(logger.getLogsForUser(1, 51)).rejects.toThrow('Limit must not exceed 50');
    });

    it('should use default limit of 100', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      await logger.getLogsForUser(42);

      const [, params] = vi.mocked(executor.query).mock.calls[0]!;
      expect(params![params!.length - 1]).toBe(100);
    });

    it('should pass correct query parameters', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      await logger.getLogsForUser(99, 25);

      const [sql, params] = vi.mocked(executor.query).mock.calls[0]!;
      expect(sql).toContain('user_id');
      expect(params).toContain(99);
      expect(params![params!.length - 1]).toBe(25);
    });
  });

  describe('verify()', () => {
    it('should return true for valid HMAC checksum', () => {
      const timestamp = '2026-02-13 12:00:00';
      const action = 'user.login';
      const entityType = 'user';
      const entityId = '42';
      const data = { status: 'success' };
      const userAgent = 'unknown';

      const envelope = { meta: { user_agent: userAgent, timestamp }, data };
      const dataJson = JSON.stringify(envelope);

      const checksum = computeTestChecksum(
        timestamp,
        42,
        '127.0.0.1',
        action,
        entityType,
        entityId,
        dataJson
      );

      const result: AuditLogResult = {
        id: 1,
        timestamp: new Date('2026-02-13T12:00:00.000Z'),
        userId: 42,
        ipAddress: '127.0.0.1',
        action,
        entityType,
        entityId,
        data,
        userAgent,
        dataError: null,
        checksum,
      };

      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres');

      expect(logger.verify(result)).toBe(true);
    });

    it('should return false for tampered data', () => {
      const timestamp = '2026-02-13 12:00:00';
      const action = 'user.login';
      const entityType = 'user';
      const entityId = '42';
      const data = { status: 'success' };
      const userAgent = 'unknown';

      const envelope = { meta: { user_agent: userAgent, timestamp }, data };
      const dataJson = JSON.stringify(envelope);

      const checksum = computeTestChecksum(
        timestamp,
        42,
        '127.0.0.1',
        action,
        entityType,
        entityId,
        dataJson
      );

      const result: AuditLogResult = {
        id: 1,
        timestamp: new Date('2026-02-13T12:00:00.000Z'),
        userId: 42,
        ipAddress: '127.0.0.1',
        action,
        entityType,
        entityId,
        data: { status: 'failure' }, // Tampered
        userAgent,
        dataError: null,
        checksum,
      };

      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres');

      expect(logger.verify(result)).toBe(false);
    });

    it('should handle null data', () => {
      const timestamp = '2026-02-13 12:00:00';
      const action = 'user.login';
      const entityType = 'user';
      const entityId = '42';
      const userAgent = 'unknown';

      const envelope = { meta: { user_agent: userAgent, timestamp }, data: {} };
      const dataJson = JSON.stringify(envelope);

      const checksum = computeTestChecksum(
        timestamp,
        null,
        '127.0.0.1',
        action,
        entityType,
        entityId,
        dataJson
      );

      const result: AuditLogResult = {
        id: 1,
        timestamp: new Date('2026-02-13T12:00:00.000Z'),
        userId: null,
        ipAddress: '127.0.0.1',
        action,
        entityType,
        entityId,
        data: null,
        userAgent,
        dataError: null,
        checksum,
      };

      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres');

      expect(logger.verify(result)).toBe(false);
    });

    it('should verify correctly when data is null and checksum matches null data', () => {
      const timestamp = '2026-02-13 12:00:00';
      const action = 'user.login';
      const entityType = 'user';
      const entityId = '42';
      const userAgent = 'unknown';

      const envelope = { meta: { user_agent: userAgent, timestamp }, data: null };
      const dataJson = JSON.stringify(envelope);

      const checksum = computeTestChecksum(
        timestamp,
        null,
        '127.0.0.1',
        action,
        entityType,
        entityId,
        dataJson
      );

      const result: AuditLogResult = {
        id: 1,
        timestamp: new Date('2026-02-13T12:00:00.000Z'),
        userId: null,
        ipAddress: '127.0.0.1',
        action,
        entityType,
        entityId,
        data: null,
        userAgent,
        dataError: null,
        checksum,
      };

      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres');

      expect(logger.verify(result)).toBe(true);
    });

    it('should return false when dataError is set', () => {
      const result: AuditLogResult = {
        id: 1,
        timestamp: new Date('2026-02-13T12:00:00.000Z'),
        userId: null,
        ipAddress: '127.0.0.1',
        action: 'test',
        entityType: 'test',
        entityId: '1',
        data: null,
        userAgent: 'unknown',
        dataError: 'corrupt data',
        checksum: 'a'.repeat(64),
      };

      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres');

      expect(logger.verify(result)).toBe(false);
    });
  });

  describe('readFileLog()', () => {
    it('should return empty array when no logFilePath is set', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres');

      const results = await logger.readFileLog();
      expect(results).toEqual([]);
    });

    it('should read and decrypt file log entries', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
        logFilePath: tempLogFile,
      });

      await logger.log(
        new AuditLogEntry({
          action: 'user.login',
          entityType: 'user',
          entityId: 42,
          userId: 42,
          ipAddress: '127.0.0.1',
          userAgent: 'Vitest/1.0',
          data: { status: 'success' },
        })
      );

      const results = await logger.readFileLog();

      expect(results).toHaveLength(1);
      expect(results[0]!.action).toBe('user.login');
      expect(results[0]!.entityType).toBe('user');
      expect(results[0]!.entityId).toBe('42');
      expect(results[0]!.userId).toBe(42);
      expect(results[0]!.userAgent).toBe('Vitest/1.0');
      expect(results[0]!.data).toEqual({ status: 'success' });
      expect(results[0]!.dataError).toBeNull();
    });
  });

  describe('custom table name', () => {
    it('should use custom table name in INSERT queries', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
        tableName: 'custom_audit_table',
      });

      await logger.log(
        new AuditLogEntry({ action: 'test.action', entityType: 'test', entityId: 1 })
      );

      const [sql] = vi.mocked(executor.execute).mock.calls[0]!;
      expect(sql).toContain('INSERT INTO custom_audit_table');
    });

    it('should use custom table name in SELECT queries', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
        tableName: 'custom_logs',
      });

      await logger.getLogsForEntity('user', 1);

      const [sql] = vi.mocked(executor.query).mock.calls[0]!;
      expect(sql).toContain('FROM custom_logs');
    });

    it('should throw StorageError for invalid table name', () => {
      const executor = createMockExecutor();

      expect(
        () =>
          new AuditLogger(executor, encryptionKey, 'postgres', {
            encryption: new DatabaseEncryption(),
            tableName: 'invalid-table-name!',
          })
      ).toThrow(StorageError);

      expect(
        () =>
          new AuditLogger(executor, encryptionKey, 'postgres', {
            tableName: 'invalid-table-name!',
          })
      ).toThrow('Invalid table name');
    });
  });

  describe('mapResults()', () => {
    it('should handle null user_id', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockResolvedValue([
        {
          id: 1,
          timestamp: '2026-02-13 12:00:00',
          user_id: null,
          ip_address: '127.0.0.1',
          action: 'system.cleanup',
          entity_type: 'system',
          entity_id: '1',
          data_decrypted: null,
          checksum: 'a'.repeat(64),
        },
      ]);

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      const results = await logger.getLogsForEntity('system', 1);

      expect(results[0]!.userId).toBeNull();
      expect(results[0]!.data).toBeNull();
    });

    it('should handle empty data string', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockResolvedValue([
        {
          id: 1,
          timestamp: '2026-02-13 12:00:00',
          user_id: 1,
          ip_address: '127.0.0.1',
          action: 'test',
          entity_type: 'test',
          entity_id: '1',
          data_decrypted: '',
          checksum: 'a'.repeat(64),
        },
      ]);

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      const results = await logger.getLogsForEntity('test', 1);

      expect(results[0]!.data).toBeNull();
    });

    it('should set dataError for invalid JSON in data', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockResolvedValue([
        {
          id: 1,
          timestamp: '2026-02-13 12:00:00',
          user_id: 1,
          ip_address: '127.0.0.1',
          action: 'test',
          entity_type: 'test',
          entity_id: '1',
          data_decrypted: 'not-valid-json',
          checksum: 'a'.repeat(64),
        },
      ]);

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      const results = await logger.getLogsForEntity('test', 1);

      expect(results[0]!.data).toBeNull();
      expect(results[0]!.dataError).toMatch(/^Corrupted JSON data: /);
    });

    it('should handle null data with app encryption', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockResolvedValue([
        {
          id: 1,
          timestamp: '2026-02-13 12:00:00',
          user_id: 1,
          ip_address: '127.0.0.1',
          action: 'test',
          entity_type: 'test',
          entity_id: '1',
          data: null,
          checksum: 'a'.repeat(64),
        },
      ]);

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new AppEncryption(),
      });

      const results = await logger.getLogsForEntity('test', 1);

      expect(results[0]!.data).toBeNull();
    });

    it('should throw StorageError for missing required fields', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockResolvedValue([
        {
          id: 1,
          timestamp: '2026-02-13 12:00:00',
          // missing: user_id, ip_address, action, entity_type, entity_id, checksum
        },
      ]);

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      await expect(logger.getLogsForEntity('test', 1)).rejects.toThrow(StorageError);
      vi.mocked(executor.query).mockResolvedValue([
        {
          id: 1,
          timestamp: '2026-02-13 12:00:00',
        },
      ]);
      await expect(logger.getLogsForEntity('test', 1)).rejects.toThrow('Missing required fields');
    });

    it('should throw StorageError for missing id field', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockResolvedValue([
        {
          // id intentionally missing
          timestamp: '2026-02-13 12:00:00',
          user_id: 1,
          ip_address: '127.0.0.1',
          action: 'test',
          entity_type: 'test',
          entity_id: '1',
          data_decrypted: null,
          checksum: 'a'.repeat(64),
        },
      ]);

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      await expect(logger.getLogsForEntity('test', 1)).rejects.toThrow(StorageError);
      await expect(logger.getLogsForEntity('test', 1)).rejects.toThrow('id');
    });

    it('should throw StorageError when data_decrypted field is missing', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockResolvedValue([
        {
          id: 1,
          timestamp: '2026-02-13 12:00:00',
          user_id: 1,
          ip_address: '127.0.0.1',
          action: 'test',
          entity_type: 'test',
          entity_id: '1',
          checksum: 'a'.repeat(64),
          // data_decrypted intentionally missing
        },
      ]);

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      await expect(logger.getLogsForEntity('test', 1)).rejects.toThrow(StorageError);
      await expect(logger.getLogsForEntity('test', 1)).rejects.toThrow(
        'Missing required field "data_decrypted"'
      );
    });

    it('should throw StorageError when data field is missing with app encryption', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockResolvedValue([
        {
          id: 1,
          timestamp: '2026-02-13 12:00:00',
          user_id: 1,
          ip_address: '127.0.0.1',
          action: 'test',
          entity_type: 'test',
          entity_id: '1',
          checksum: 'a'.repeat(64),
          // data intentionally missing
        },
      ]);

      const logger = new AuditLogger(executor, encryptionKey, 'postgres');

      await expect(logger.getLogsForEntity('test', 1)).rejects.toThrow(StorageError);
      await expect(logger.getLogsForEntity('test', 1)).rejects.toThrow(
        'Missing required field "data"'
      );
    });
  });

  describe('mysql dialect with app encryption', () => {
    it('should use ? placeholders for INSERT with app encryption', async () => {
      const mockEncryption: EncryptionInterface = {
        encrypt: vi.fn().mockReturnValue('encrypted-data'),
        decrypt: vi.fn(),
      };

      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'mysql', {
        encryption: mockEncryption,
      });

      await logger.log(new AuditLogEntry({ action: 'test', entityType: 'test', entityId: 1 }));

      const [sql] = vi.mocked(executor.execute).mock.calls[0]!;
      expect(sql).toContain('?');
      expect(sql).not.toContain('$1');
      expect(sql).not.toContain('encrypt_text');
    });

    it('should use ? placeholders for SELECT with app encryption', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'mysql', {
        encryption: new AppEncryption(),
      });

      await logger.getLogsForEntity('user', 42);

      const [sql] = vi.mocked(executor.query).mock.calls[0]!;
      expect(sql).toContain('?');
      expect(sql).not.toContain('$1');
      expect(sql).not.toContain('decrypt_text');
    });

    it('should use ? placeholders for getLogsForUser with app encryption', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'mysql', {
        encryption: new AppEncryption(),
      });

      await logger.getLogsForUser(1);

      const [sql] = vi.mocked(executor.query).mock.calls[0]!;
      expect(sql).toContain('?');
      expect(sql).not.toContain('$1');
    });
  });

  describe('file logging edge cases', () => {
    it('should silently ignore file write error after successful db write', async () => {
      const impossibleLogFile = '/dev/null/impossible/path/audit.log';

      const executor = createMockExecutor();

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
        logFilePath: impossibleLogFile,
      });

      // DB succeeds, file write fails — should not propagate to caller
      await expect(
        logger.log(new AuditLogEntry({ action: 'test', entityType: 'test', entityId: 1 }))
      ).resolves.toBeUndefined();

      expect(executor.execute).toHaveBeenCalledOnce();
    });
  });

  describe('query error handling', () => {
    it('should wrap getLogsForEntity query errors in StorageError', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockRejectedValue(new Error('Connection refused'));

      const logger = new AuditLogger(executor, encryptionKey, 'postgres');

      await expect(logger.getLogsForEntity('user', 1)).rejects.toThrow(StorageError);
      vi.mocked(executor.query).mockRejectedValue(new Error('Connection refused'));
      await expect(logger.getLogsForEntity('user', 1)).rejects.toThrow(
        'Failed to query audit logs: Connection refused'
      );
    });

    it('should wrap getLogsForUser query errors in StorageError', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockRejectedValue(new Error('Timeout'));

      const logger = new AuditLogger(executor, encryptionKey, 'postgres');

      await expect(logger.getLogsForUser(1)).rejects.toThrow(StorageError);
      vi.mocked(executor.query).mockRejectedValue(new Error('Timeout'));
      await expect(logger.getLogsForUser(1)).rejects.toThrow('Failed to query audit logs: Timeout');
    });

    it('should handle non-Error query rejection', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockRejectedValue('raw string error');

      const logger = new AuditLogger(executor, encryptionKey, 'postgres');

      await expect(logger.getLogsForEntity('user', 1)).rejects.toThrow(StorageError);
      vi.mocked(executor.query).mockRejectedValue('raw string error');
      await expect(logger.getLogsForEntity('user', 1)).rejects.toThrow('raw string error');
    });

    it('should handle non-Error query rejection in getLogsForUser', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockRejectedValue('raw user query error');

      const logger = new AuditLogger(executor, encryptionKey, 'postgres');

      await expect(logger.getLogsForUser(1)).rejects.toThrow(StorageError);
      vi.mocked(executor.query).mockRejectedValue('raw user query error');
      await expect(logger.getLogsForUser(1)).rejects.toThrow('raw user query error');
    });
  });

  describe('verify() edge cases', () => {
    it('should return false for mismatched checksum length', () => {
      const result: AuditLogResult = {
        id: 1,
        timestamp: new Date('2026-02-13T12:00:00.000Z'),
        userId: null,
        ipAddress: '127.0.0.1',
        action: 'test',
        entityType: 'test',
        entityId: '1',
        data: {},
        userAgent: 'unknown',
        dataError: null,
        checksum: 'abc',
      };

      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres');

      expect(logger.verify(result)).toBe(false);
    });

    it('should return false when JSON.stringify fails (e.g. BigInt in data)', () => {
      const result: AuditLogResult = {
        id: 1,
        timestamp: new Date('2026-02-13T12:00:00.000Z'),
        userId: null,
        ipAddress: '127.0.0.1',
        action: 'test',
        entityType: 'test',
        entityId: '1',
        data: { value: BigInt(42) } as unknown as Record<string, unknown>,
        userAgent: 'unknown',
        dataError: null,
        checksum: 'a'.repeat(64),
      };

      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres');

      expect(logger.verify(result)).toBe(false);
    });
  });

  describe('mapResults() edge cases', () => {
    it('should default to unknown when user_agent in meta is not a string', async () => {
      const envelope = {
        meta: { user_agent: 12345, timestamp: '2026-02-13 12:00:00' },
        data: { test: 'data' },
      };
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockResolvedValue([
        {
          id: 1,
          timestamp: '2026-02-13 12:00:00',
          user_id: 1,
          ip_address: '127.0.0.1',
          action: 'test',
          entity_type: 'test',
          entity_id: '1',
          data_decrypted: JSON.stringify(envelope),
          checksum: 'a'.repeat(64),
        },
      ]);

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      const results = await logger.getLogsForEntity('test', 1);
      expect(results[0]!.userAgent).toBe('unknown');
      expect(results[0]!.data).toEqual({ test: 'data' });
    });

    it('should throw StorageError for invalid timestamp in database row', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockResolvedValue([
        {
          id: 1,
          timestamp: 'not-a-date',
          user_id: 1,
          ip_address: '127.0.0.1',
          action: 'test',
          entity_type: 'test',
          entity_id: '1',
          data_decrypted: JSON.stringify({
            meta: { user_agent: 'test', timestamp: '2026-02-13 12:00:00' },
            data: {},
          }),
          checksum: 'a'.repeat(64),
        },
      ]);

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      await expect(logger.getLogsForEntity('test', 1)).rejects.toThrow(StorageError);
      await expect(logger.getLogsForEntity('test', 1)).rejects.toThrow(
        'Invalid timestamp in audit log'
      );
    });

    it('should handle non-object JSON data (array)', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockResolvedValue([
        {
          id: 1,
          timestamp: '2026-02-13 12:00:00',
          user_id: 1,
          ip_address: '127.0.0.1',
          action: 'test',
          entity_type: 'test',
          entity_id: '1',
          data_decrypted: '[1, 2, 3]',
          checksum: 'a'.repeat(64),
        },
      ]);

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      const results = await logger.getLogsForEntity('test', 1);

      expect(results[0]!.data).toBeNull();
      expect(results[0]!.dataError).toBeNull();
    });

    it('should handle non-object data inside envelope', async () => {
      const executor = createMockExecutor();
      const envelope = JSON.stringify({
        meta: { user_agent: 'TestAgent', timestamp: '2026-02-13 12:00:00' },
        data: 'not-an-object',
      });
      vi.mocked(executor.query).mockResolvedValue([
        {
          id: 1,
          timestamp: '2026-02-13 12:00:00',
          user_id: 1,
          ip_address: '127.0.0.1',
          action: 'test',
          entity_type: 'test',
          entity_id: '1',
          data_decrypted: envelope,
          checksum: 'a'.repeat(64),
        },
      ]);

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      const results = await logger.getLogsForEntity('test', 1);

      expect(results[0]!.data).toBeNull();
      expect(results[0]!.userAgent).toBe('TestAgent');
    });
  });

  describe('constructor typed exceptions', () => {
    it('should throw AuditLogError for short encryption key', () => {
      const executor = createMockExecutor();
      expect(() => new AuditLogger(executor, 'short', 'postgres')).toThrow(AuditLogError);
    });

    it('should throw AuditLogError for invalid maxLimit', () => {
      const executor = createMockExecutor();
      expect(() => new AuditLogger(executor, encryptionKey, 'postgres', { maxLimit: 0 })).toThrow(
        AuditLogError
      );
    });

    it('should throw AuditLogError for limit < 1', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres');

      await expect(logger.getLogsForEntity('user', 1, 0)).rejects.toThrow(AuditLogError);
    });

    it('should throw AuditLogError when limit exceeds maxLimit', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', { maxLimit: 10 });

      await expect(logger.getLogsForEntity('user', 1, 11)).rejects.toThrow(AuditLogError);
    });
  });

  describe('verify() individual field tamper detection', () => {
    function createVerifyResult(
      resultOverrides: Partial<AuditLogResult> = {},
      checksumUserId: number | null = 42
    ): { result: AuditLogResult; logger: AuditLogger } {
      const timestamp = '2026-02-13 12:00:00';
      const ipAddress = '127.0.0.1';
      const action = 'user.login';
      const entityType = 'user';
      const entityId = '42';
      const data = { status: 'success' };
      const userAgent = 'TestAgent/1.0';

      const envelope = { meta: { user_agent: userAgent, timestamp }, data };
      const dataJson = JSON.stringify(envelope);
      const checksum = computeTestChecksum(
        timestamp,
        checksumUserId,
        ipAddress,
        action,
        entityType,
        entityId,
        dataJson
      );

      const result: AuditLogResult = {
        id: 1,
        timestamp: new Date('2026-02-13T12:00:00.000Z'),
        userId: 42,
        ipAddress,
        action,
        entityType,
        entityId,
        data,
        userAgent,
        dataError: null,
        checksum,
        ...resultOverrides,
      };

      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres');
      return { result, logger };
    }

    it('should return false for tampered userId', () => {
      const { result, logger } = createVerifyResult({ userId: 99 });
      expect(logger.verify(result)).toBe(false);
    });

    it('should return false for tampered ipAddress', () => {
      const { result, logger } = createVerifyResult({ ipAddress: '10.0.0.1' });
      expect(logger.verify(result)).toBe(false);
    });

    it('should return false for tampered action', () => {
      const { result, logger } = createVerifyResult({ action: 'user.logout' });
      expect(logger.verify(result)).toBe(false);
    });

    it('should return false for tampered entityType', () => {
      const { result, logger } = createVerifyResult({ entityType: 'admin' });
      expect(logger.verify(result)).toBe(false);
    });

    it('should return false for tampered entityId', () => {
      const { result, logger } = createVerifyResult({ entityId: '99' });
      expect(logger.verify(result)).toBe(false);
    });

    it('should return false for tampered timestamp', () => {
      const { result, logger } = createVerifyResult({
        timestamp: new Date('2026-02-13T12:00:01.000Z'),
      });
      expect(logger.verify(result)).toBe(false);
    });

    it('should return false when null userId checksum is used with non-null userId result', () => {
      const { result, logger } = createVerifyResult({ userId: 99 }, null);
      expect(logger.verify(result)).toBe(false);
    });

    it('should return false when non-null userId checksum is verified with null userId result', () => {
      const { result, logger } = createVerifyResult({ userId: null });
      expect(logger.verify(result)).toBe(false);
    });
  });

  describe('verify() log+verify integration roundtrip', () => {
    it('should verify a correctly constructed result (log+verify integration)', () => {
      const timestamp = '2026-02-13 12:00:00';
      const userId = 42;
      const ipAddress = '127.0.0.1';
      const action = 'user.login';
      const entityType = 'user';
      const entityId = '42';
      const data = { status: 'success' };
      const userAgent = 'TestAgent/1.0';

      const envelope = { meta: { user_agent: userAgent, timestamp }, data };
      const dataJson = JSON.stringify(envelope);
      const checksum = computeTestChecksum(
        timestamp,
        userId,
        ipAddress,
        action,
        entityType,
        entityId,
        dataJson
      );

      const result: AuditLogResult = {
        id: 1,
        timestamp: new Date('2026-02-13T12:00:00.000Z'),
        userId,
        ipAddress,
        action,
        entityType,
        entityId,
        data,
        userAgent,
        dataError: null,
        checksum,
      };

      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres');
      expect(logger.verify(result)).toBe(true);
    });

    it('should verify a correctly constructed result with null userId', () => {
      const timestamp = '2026-02-13 12:00:00';
      const ipAddress = '127.0.0.1';
      const action = 'user.login';
      const entityType = 'user';
      const entityId = '42';
      const data = { status: 'success' };
      const userAgent = 'TestAgent/1.0';

      const envelope = { meta: { user_agent: userAgent, timestamp }, data };
      const dataJson = JSON.stringify(envelope);
      const checksum = computeTestChecksum(
        timestamp,
        null,
        ipAddress,
        action,
        entityType,
        entityId,
        dataJson
      );

      const result: AuditLogResult = {
        id: 1,
        timestamp: new Date('2026-02-13T12:00:00.000Z'),
        userId: null,
        ipAddress,
        action,
        entityType,
        entityId,
        data,
        userAgent,
        dataError: null,
        checksum,
      };

      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres');
      expect(logger.verify(result)).toBe(true);
    });

    it('should verify file log results after log+readFileLog roundtrip', async () => {
      // FileLogReader parses timestamps via new Date(string) which interprets
      // 'YYYY-MM-DD HH:MM:SS' as local time. Force UTC so the roundtrip is lossless.
      const originalTZ = process.env['TZ'];
      process.env['TZ'] = 'UTC';

      try {
        const executor = createMockExecutor();
        const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
          encryption: new DatabaseEncryption(),
          logFilePath: tempLogFile,
        });

        await logger.log(
          new AuditLogEntry({
            action: 'user.login',
            entityType: 'user',
            entityId: 42,
            userId: 42,
            ipAddress: '127.0.0.1',
            userAgent: 'Vitest/1.0',
            data: { status: 'success' },
          })
        );

        const results = await logger.readFileLog();
        expect(results).toHaveLength(1);
        expect(logger.verify(results[0]!)).toBe(true);
      } finally {
        process.env['TZ'] = originalTZ;
      }
    });
  });

  describe('file logging security', () => {
    it('should create file with restricted permissions (0600)', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
        logFilePath: tempLogFile,
      });

      await logger.log(new AuditLogEntry({ action: 'test', entityType: 'test', entityId: 1 }));

      const stats = statSync(tempLogFile);
      // Check permissions: 0o600 = owner read+write only
      const mode = stats.mode & 0o777;
      expect(mode).toBe(0o600);
    });

    it('should use AppEncryption for file log even when using DatabaseEncryption', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
        logFilePath: tempLogFile,
      });

      await logger.log(
        new AuditLogEntry({
          action: 'user.login',
          entityType: 'user',
          entityId: 42,
          userId: 42,
          data: { status: 'success' },
        })
      );

      // File should be encrypted with AppEncryption, not plaintext
      const content = readFileSync(tempLogFile, 'utf8').trim();
      // Verify it's valid base64 (AppEncryption output)
      expect(content).toMatch(/^[A-Za-z0-9+/]+=*$/);

      // Should be decryptable with AppEncryption
      const appEncryption = new AppEncryption();
      const decrypted = appEncryption.decrypt(content, encryptionKey);
      const parsed = JSON.parse(decrypted) as Record<string, unknown>;
      expect(parsed['action']).toBe('user.login');
    });

    it('should write all required fields to file log', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
        logFilePath: tempLogFile,
      });

      await logger.log(
        new AuditLogEntry({
          action: 'user.login',
          entityType: 'user',
          entityId: 42,
          userId: 99,
          ipAddress: '10.0.0.1',
          userAgent: 'Agent/1.0',
          data: { method: '2fa' },
        })
      );

      const content = readFileSync(tempLogFile, 'utf8');
      // Verify file ends with newline
      expect(content.endsWith('\n')).toBe(true);

      const appEncryption = new AppEncryption();
      const decrypted = appEncryption.decrypt(content.trim(), encryptionKey);
      const parsed = JSON.parse(decrypted) as Record<string, unknown>;

      // Verify all 9 required fields are present
      expect(parsed).toHaveProperty('timestamp');
      expect(parsed).toHaveProperty('user_id');
      expect(parsed).toHaveProperty('ip_address');
      expect(parsed).toHaveProperty('user_agent');
      expect(parsed).toHaveProperty('action');
      expect(parsed).toHaveProperty('entity_type');
      expect(parsed).toHaveProperty('entity_id');
      expect(parsed).toHaveProperty('data');
      expect(parsed).toHaveProperty('checksum');

      // Verify field values
      expect(parsed['user_id']).toBe(99);
      expect(parsed['ip_address']).toBe('10.0.0.1');
      expect(parsed['user_agent']).toBe('Agent/1.0');
      expect(parsed['action']).toBe('user.login');
      expect(parsed['entity_type']).toBe('user');
      expect(parsed['entity_id']).toBe('42');
      expect((parsed['data'] as Record<string, unknown>)['method']).toBe('2fa');
    });

    it('should create nested directories for log file', async () => {
      const nestedPath = join(tmpdir(), `audit-nested-${Date.now()}`, 'sub', 'deep', 'audit.log');

      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
        logFilePath: nestedPath,
      });

      await logger.log(new AuditLogEntry({ action: 'test', entityType: 'test', entityId: 1 }));

      expect(existsSync(nestedPath)).toBe(true);

      // Cleanup
      unlinkSync(nestedPath);
      rmdirSync(dirname(nestedPath));
      rmdirSync(dirname(dirname(nestedPath)));
      rmdirSync(dirname(dirname(dirname(nestedPath))));
    });
  });

  describe('boundary tests', () => {
    it('should accept data at exactly MAX_ENCODED_DATA_SIZE (10000 bytes)', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      // Build data that produces exactly 10000 bytes when JSON-serialized as envelope
      // The envelope adds: {"meta":{"user_agent":"unknown","timestamp":"2026-02-13 12:00:00"},"data":{"x":"..."}}
      // We need to find a payload size that makes the total exactly 10000
      // Envelope overhead is roughly 75 bytes, so data value should be ~9920 chars
      // Let's use a binary search approach: create data, check size, adjust
      const baseEnvelope = JSON.stringify({
        meta: { user_agent: 'unknown', timestamp: '2026-02-13 12:00:00' },
        data: { x: '' },
      });
      const overhead = Buffer.byteLength(baseEnvelope); // without the value
      const fillSize = 10000 - overhead;

      await expect(
        logger.log(
          new AuditLogEntry({
            action: 'test',
            entityType: 'test',
            entityId: 1,
            data: { x: 'a'.repeat(fillSize) },
          })
        )
      ).resolves.toBeUndefined();

      expect(executor.execute).toHaveBeenCalledOnce();
    });

    it('should reject data at MAX_ENCODED_DATA_SIZE + 1 byte', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      const baseEnvelope = JSON.stringify({
        meta: { user_agent: 'unknown', timestamp: '2026-02-13 12:00:00' },
        data: { x: '' },
      });
      const overhead = Buffer.byteLength(baseEnvelope);
      const fillSize = 10000 - overhead + 1;

      await expect(
        logger.log(
          new AuditLogEntry({
            action: 'test',
            entityType: 'test',
            entityId: 1,
            data: { x: 'a'.repeat(fillSize) },
          })
        )
      ).rejects.toThrow('Encoded data size exceeds maximum');
    });

    it('should accept getLogsForEntity with limit of 1', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres');

      await logger.getLogsForEntity('user', 1, 1);
      expect(executor.query).toHaveBeenCalledOnce();
    });

    it('should accept getLogsForEntity with limit exactly at maxLimit', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', { maxLimit: 50 });

      await logger.getLogsForEntity('user', 1, 50);
      expect(executor.query).toHaveBeenCalledOnce();
    });

    it('should reject getLogsForEntity with limit exceeding maxLimit by 1', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', { maxLimit: 50 });

      await expect(logger.getLogsForEntity('user', 1, 51)).rejects.toThrow(
        'Limit must not exceed 50'
      );
    });

    it('should allow any limit when maxLimit is undefined', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres');

      await logger.getLogsForEntity('user', 1, 999999);
      expect(executor.query).toHaveBeenCalledOnce();
    });
  });

  describe('mutation-killer tests', () => {
    it('should cast userId to number in mapResults', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockResolvedValue([
        {
          id: 1,
          timestamp: '2026-02-13 12:00:00',
          user_id: '42', // String from DB — must be cast to number
          ip_address: '127.0.0.1',
          action: 'test',
          entity_type: 'test',
          entity_id: '1',
          data_decrypted: null,
          checksum: 'a'.repeat(64),
        },
      ]);

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      const results = await logger.getLogsForEntity('test', 1);
      expect(results[0]!.userId).toBe(42);
      expect(typeof results[0]!.userId).toBe('number');
    });

    it('should cast entityId to string in mapResults', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockResolvedValue([
        {
          id: 1,
          timestamp: '2026-02-13 12:00:00',
          user_id: 1,
          ip_address: '127.0.0.1',
          action: 'test',
          entity_type: 'test',
          entity_id: 42, // Number from DB — must be cast to string
          data_decrypted: null,
          checksum: 'a'.repeat(64),
        },
      ]);

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      const results = await logger.getLogsForEntity('test', 1);
      expect(results[0]!.entityId).toBe('42');
      expect(typeof results[0]!.entityId).toBe('string');
    });

    it('should preserve slashes and unicode in file log', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
        logFilePath: tempLogFile,
      });

      await logger.log(
        new AuditLogEntry({
          action: 'test',
          entityType: 'test',
          entityId: 1,
          data: { url: 'https://example.com/path', emoji: '\u{1F512}' },
        })
      );

      const appEncryption = new AppEncryption();
      const content = readFileSync(tempLogFile, 'utf8');
      const decrypted = appEncryption.decrypt(content.trim(), encryptionKey);
      const parsed = JSON.parse(decrypted) as Record<string, unknown>;
      const data = parsed['data'] as Record<string, unknown>;

      expect(data['url']).toBe('https://example.com/path');
      expect(data['emoji']).toBe('\u{1F512}');
    });

    it('should include all required fields in database INSERT params', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      await logger.log(
        new AuditLogEntry({
          action: 'user.login',
          entityType: 'user',
          entityId: 42,
          userId: 99,
          ipAddress: '10.0.0.1',
          userAgent: 'Agent/1.0',
          data: { method: '2fa' },
        })
      );

      const [, params] = vi.mocked(executor.execute).mock.calls[0]!;
      // Params should include: timestamp, userId, ipAddress, action, entityType, entityId, dataJson, dbEncryptionKey, checksum
      expect(params).toContain(99); // userId
      expect(params).toContain('10.0.0.1'); // ipAddress
      expect(params).toContain('user.login'); // action
      expect(params).toContain('user'); // entityType
      expect(params).toContain('42'); // entityId (as string)
    });

    it('should reject table name exceeding 128 characters', () => {
      const executor = createMockExecutor();
      const longName = 'a'.repeat(129);
      expect(
        () => new AuditLogger(executor, encryptionKey, 'postgres', { tableName: longName })
      ).toThrow(StorageError);
      expect(
        () => new AuditLogger(executor, encryptionKey, 'postgres', { tableName: longName })
      ).toThrow('Table name exceeds maximum length of 128 characters');
    });

    it('should accept table name at exactly 128 characters', async () => {
      const executor = createMockExecutor();
      const maxName = 'a'.repeat(128);
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', { tableName: maxName });

      await logger.log(new AuditLogEntry({ action: 'test', entityType: 'test', entityId: '1' }));

      const [sql] = vi.mocked(executor.execute).mock.calls[0]!;
      expect(sql).toContain(`INSERT INTO ${maxName}`);
    });

    it('should reject table name starting with a digit', () => {
      const executor = createMockExecutor();
      expect(
        () => new AuditLogger(executor, encryptionKey, 'postgres', { tableName: '1invalid' })
      ).toThrow(StorageError);
      expect(
        () => new AuditLogger(executor, encryptionKey, 'postgres', { tableName: '1invalid' })
      ).toThrow('Invalid table name');
    });

    it('should include error message in query exception for getLogsForEntity', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockRejectedValue(new Error('SQLSTATE[HY000] connection refused'));

      const logger = new AuditLogger(executor, encryptionKey, 'postgres');

      await expect(logger.getLogsForEntity('user', 1)).rejects.toThrow(
        'Failed to query audit logs: SQLSTATE[HY000] connection refused'
      );
    });

    it('should include error message in query exception for getLogsForUser', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockRejectedValue(new Error('SQLSTATE[HY000] timeout'));

      const logger = new AuditLogger(executor, encryptionKey, 'postgres');

      await expect(logger.getLogsForUser(1)).rejects.toThrow(
        'Failed to query audit logs: SQLSTATE[HY000] timeout'
      );
    });

    it('should include timestamp value in invalid timestamp error', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockResolvedValue([
        {
          id: 1,
          timestamp: 'garbage-timestamp',
          user_id: 1,
          ip_address: '127.0.0.1',
          action: 'test',
          entity_type: 'test',
          entity_id: '1',
          data_decrypted: null,
          checksum: 'a'.repeat(64),
        },
      ]);

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      await expect(logger.getLogsForEntity('test', 1)).rejects.toThrow('garbage-timestamp');
    });

    it('should handle undefined user_id same as null', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockResolvedValue([
        {
          id: 1,
          timestamp: '2026-02-13 12:00:00',
          user_id: undefined,
          ip_address: '127.0.0.1',
          action: 'test',
          entity_type: 'test',
          entity_id: '1',
          data_decrypted: null,
          checksum: 'a'.repeat(64),
        },
      ]);

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      const results = await logger.getLogsForEntity('test', 1);
      expect(results[0]!.userId).toBeNull();
    });
  });

  describe('writeWithLock()', () => {
    it('should create and clean up lock file on successful write', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
        logFilePath: tempLogFile,
      });

      await logger.log(new AuditLogEntry({ action: 'test', entityType: 'test', entityId: 1 }));

      // Log file was written
      expect(existsSync(tempLogFile)).toBe(true);
      // Lock file was cleaned up
      expect(existsSync(`${tempLogFile}.lock`)).toBe(false);
    });

    it('should silently ignore file write error after successful db write', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
        logFilePath: '/dev/null/impossible.log',
      });

      // DB succeeds, file write fails — error is silently ignored
      await expect(
        logger.log(new AuditLogEntry({ action: 'test', entityType: 'test', entityId: 1 }))
      ).resolves.toBeUndefined();

      expect(executor.execute).toHaveBeenCalledOnce();
    });

    it('should succeed despite lock file after successful db write', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
        logFilePath: tempLogFile,
      });

      // Pre-create the lock file to simulate concurrent access
      writeFileSync(`${tempLogFile}.lock`, '');

      // DB succeeds, file write fails due to lock — silently ignored
      await expect(
        logger.log(new AuditLogEntry({ action: 'test', entityType: 'test', entityId: 1 }))
      ).resolves.toBeUndefined();

      expect(executor.execute).toHaveBeenCalledOnce();
    });

    it('should remove stale lock file and proceed with write', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
        logFilePath: tempLogFile,
      });

      // Pre-create a stale lock file (mtime 61 seconds ago)
      const lockPath = `${tempLogFile}.lock`;
      writeFileSync(lockPath, '');
      const staleTime = new Date(Date.now() - 61_000);
      utimesSync(lockPath, staleTime, staleTime);

      await logger.log(new AuditLogEntry({ action: 'test', entityType: 'test', entityId: 1 }));

      expect(existsSync(tempLogFile)).toBe(true);
      expect(existsSync(lockPath)).toBe(false);
    });

    it('should succeed despite fresh lock file after successful db write', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
        logFilePath: tempLogFile,
      });

      // Pre-create a fresh lock file (just now)
      const lockPath = `${tempLogFile}.lock`;
      writeFileSync(lockPath, '');

      // DB succeeds, file write fails due to fresh lock — silently ignored
      await expect(
        logger.log(new AuditLogEntry({ action: 'test', entityType: 'test', entityId: 1 }))
      ).resolves.toBeUndefined();

      expect(executor.execute).toHaveBeenCalledOnce();
    });
  });

  describe('file log size limit', () => {
    it('should succeed despite full file log after successful db write', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
        logFilePath: tempLogFile,
      });

      // Create a file that exceeds MAX_FILE_LOG_SIZE using sparse file via truncate
      const fd = openSync(tempLogFile, 'w');
      ftruncateSync(fd, 10_485_760);
      closeSync(fd);

      // DB succeeds, file write fails due to size limit — silently ignored
      await expect(
        logger.log(new AuditLogEntry({ action: 'test', entityType: 'test', entityId: 1 }))
      ).resolves.toBeUndefined();

      expect(executor.execute).toHaveBeenCalledOnce();
    });

    it('should propagate StorageError through DB-error path when file is full', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.execute).mockRejectedValue(new Error('DB down'));

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
        logFilePath: tempLogFile,
      });

      const fd = openSync(tempLogFile, 'w');
      ftruncateSync(fd, 10_485_760);
      closeSync(fd);

      // DB fails, file fallback also fails because file is full → combined error
      await expect(
        logger.log(new AuditLogEntry({ action: 'test', entityType: 'test', entityId: 1 }))
      ).rejects.toThrow('File fallback also failed');
    });

    it('should include rotation hint in combined error when file is full and DB fails', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.execute).mockRejectedValue(new Error('DB down'));

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
        logFilePath: tempLogFile,
      });

      const fd = openSync(tempLogFile, 'w');
      ftruncateSync(fd, 10_485_760);
      closeSync(fd);

      await expect(
        logger.log(new AuditLogEntry({ action: 'test', entityType: 'test', entityId: 1 }))
      ).rejects.toThrow('Configure external log rotation');
    });

    it('should not include file fallback error when logFilePath is null and DB fails', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.execute).mockRejectedValue(new Error('DB down'));

      const logger = new AuditLogger(executor, encryptionKey, 'postgres');

      const error = (await logger
        .log(new AuditLogEntry({ action: 'test', entityType: 'test', entityId: 1 }))
        .catch((e: unknown) => e)) as Error;

      expect(error).toBeInstanceOf(StorageError);
      expect(error.message).toContain('DB down');
      expect(error.message).not.toContain('File fallback also failed');
    });

    it('should include file fallback error when lock file blocks write and DB fails', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.execute).mockRejectedValue(new Error('DB down'));

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
        logFilePath: tempLogFile,
      });

      writeFileSync(`${tempLogFile}.lock`, '');

      const error = (await logger
        .log(new AuditLogEntry({ action: 'test', entityType: 'test', entityId: 1 }))
        .catch((e: unknown) => e)) as Error;

      expect(error).toBeInstanceOf(StorageError);
      expect(error.message).toContain('File fallback also failed');
      expect(error.message).toContain('EEXIST');
    });

    it('should remove stale lock and write fallback file when DB fails', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.execute).mockRejectedValue(new Error('DB down'));

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
        logFilePath: tempLogFile,
      });

      const lockPath = `${tempLogFile}.lock`;
      writeFileSync(lockPath, '');
      const staleTime = new Date(Date.now() - 61_000);
      utimesSync(lockPath, staleTime, staleTime);

      // DB fails, stale lock removed, file write succeeds → no "File fallback" in error
      const error = (await logger
        .log(new AuditLogEntry({ action: 'test', entityType: 'test', entityId: 1 }))
        .catch((e: unknown) => e)) as Error;

      expect(error).toBeInstanceOf(StorageError);
      expect(error.message).not.toContain('File fallback also failed');
      expect(existsSync(tempLogFile)).toBe(true);
      expect(existsSync(lockPath)).toBe(false);
    });

    it('should not remove 59-second-old lock and fail file write when DB fails', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.execute).mockRejectedValue(new Error('DB down'));

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
        logFilePath: tempLogFile,
      });

      const lockPath = `${tempLogFile}.lock`;
      writeFileSync(lockPath, '');
      const freshTime = new Date(Date.now() - 59_000);
      utimesSync(lockPath, freshTime, freshTime);

      await expect(
        logger.log(new AuditLogEntry({ action: 'test', entityType: 'test', entityId: 1 }))
      ).rejects.toThrow('File fallback also failed');
    });
  });

  describe('validateRowSchema() type checks', () => {
    it('should throw StorageError for boolean id', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockResolvedValue([
        {
          id: true,
          timestamp: '2026-02-13 12:00:00',
          user_id: 1,
          ip_address: '127.0.0.1',
          action: 'test',
          entity_type: 'test',
          entity_id: '1',
          data_decrypted: null,
          checksum: 'a'.repeat(64),
        },
      ]);

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      await expect(logger.getLogsForEntity('test', 1)).rejects.toThrow(StorageError);
      await expect(logger.getLogsForEntity('test', 1)).rejects.toThrow(
        'Invalid type for field "id"'
      );
    });

    it('should throw StorageError for non-string/non-Date timestamp', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockResolvedValue([
        {
          id: 1,
          timestamp: 12345,
          user_id: 1,
          ip_address: '127.0.0.1',
          action: 'test',
          entity_type: 'test',
          entity_id: '1',
          data_decrypted: null,
          checksum: 'a'.repeat(64),
        },
      ]);

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      await expect(logger.getLogsForEntity('test', 1)).rejects.toThrow(StorageError);
      await expect(logger.getLogsForEntity('test', 1)).rejects.toThrow(
        'Invalid type for field "timestamp"'
      );
    });

    it('should throw StorageError for boolean user_id', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockResolvedValue([
        {
          id: 1,
          timestamp: '2026-02-13 12:00:00',
          user_id: true,
          ip_address: '127.0.0.1',
          action: 'test',
          entity_type: 'test',
          entity_id: '1',
          data_decrypted: null,
          checksum: 'a'.repeat(64),
        },
      ]);

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      await expect(logger.getLogsForEntity('test', 1)).rejects.toThrow(StorageError);
      await expect(logger.getLogsForEntity('test', 1)).rejects.toThrow(
        'Invalid type for field "user_id"'
      );
    });

    it('should throw StorageError for boolean entity_id', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockResolvedValue([
        {
          id: 1,
          timestamp: '2026-02-13 12:00:00',
          user_id: 1,
          ip_address: '127.0.0.1',
          action: 'test',
          entity_type: 'test',
          entity_id: true,
          data_decrypted: null,
          checksum: 'a'.repeat(64),
        },
      ]);

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      await expect(logger.getLogsForEntity('test', 1)).rejects.toThrow(StorageError);
      await expect(logger.getLogsForEntity('test', 1)).rejects.toThrow(
        'Invalid type for field "entity_id"'
      );
    });

    it('should throw StorageError for non-string ip_address', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockResolvedValue([
        {
          id: 1,
          timestamp: '2026-02-13 12:00:00',
          user_id: 1,
          ip_address: 12345,
          action: 'test',
          entity_type: 'test',
          entity_id: '1',
          data_decrypted: null,
          checksum: 'a'.repeat(64),
        },
      ]);

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      await expect(logger.getLogsForEntity('test', 1)).rejects.toThrow(StorageError);
      await expect(logger.getLogsForEntity('test', 1)).rejects.toThrow(
        'Invalid type for field "ip_address"'
      );
    });

    it('should throw StorageError for non-string action', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockResolvedValue([
        {
          id: 1,
          timestamp: '2026-02-13 12:00:00',
          user_id: 1,
          ip_address: '127.0.0.1',
          action: 42,
          entity_type: 'test',
          entity_id: '1',
          data_decrypted: null,
          checksum: 'a'.repeat(64),
        },
      ]);

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      await expect(logger.getLogsForEntity('test', 1)).rejects.toThrow(StorageError);
      await expect(logger.getLogsForEntity('test', 1)).rejects.toThrow(
        'Invalid type for field "action"'
      );
    });

    it('should throw StorageError for non-string entity_type', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockResolvedValue([
        {
          id: 1,
          timestamp: '2026-02-13 12:00:00',
          user_id: 1,
          ip_address: '127.0.0.1',
          action: 'test',
          entity_type: 42,
          entity_id: '1',
          data_decrypted: null,
          checksum: 'a'.repeat(64),
        },
      ]);

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      await expect(logger.getLogsForEntity('test', 1)).rejects.toThrow(StorageError);
      await expect(logger.getLogsForEntity('test', 1)).rejects.toThrow(
        'Invalid type for field "entity_type"'
      );
    });

    it('should throw StorageError for non-string checksum', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockResolvedValue([
        {
          id: 1,
          timestamp: '2026-02-13 12:00:00',
          user_id: 1,
          ip_address: '127.0.0.1',
          action: 'test',
          entity_type: 'test',
          entity_id: '1',
          data_decrypted: null,
          checksum: 12345,
        },
      ]);

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      await expect(logger.getLogsForEntity('test', 1)).rejects.toThrow(StorageError);
      await expect(logger.getLogsForEntity('test', 1)).rejects.toThrow(
        'Invalid type for field "checksum"'
      );
    });

    it('should accept numeric user_id from database', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockResolvedValue([
        {
          id: 1,
          timestamp: '2026-02-13 12:00:00',
          user_id: 42,
          ip_address: '127.0.0.1',
          action: 'test',
          entity_type: 'test',
          entity_id: '1',
          data_decrypted: null,
          checksum: 'a'.repeat(64),
        },
      ]);

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      const results = await logger.getLogsForEntity('test', 1);
      expect(results[0]!.userId).toBe(42);
    });

    it('should accept numeric entity_id from database', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockResolvedValue([
        {
          id: 1,
          timestamp: '2026-02-13 12:00:00',
          user_id: 1,
          ip_address: '127.0.0.1',
          action: 'test',
          entity_type: 'test',
          entity_id: 42,
          data_decrypted: null,
          checksum: 'a'.repeat(64),
        },
      ]);

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      const results = await logger.getLogsForEntity('test', 1);
      expect(results[0]!.entityId).toBe('42');
    });
  });

  describe('mutation-killer tests (batch 2)', () => {
    it('should use "unknown" as default ipAddress and userAgent in logAuth', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      await logger.logAuth('test.action');

      const [, params] = vi.mocked(executor.execute).mock.calls[0]!;
      // params: [timestamp, userId, ipAddress, action, entityType, entityId, dataJson, dbKey, checksum]
      expect(params![2]).toBe('unknown');
      const dataJson = params!.find(
        (p) => typeof p === 'string' && p.includes('user_agent')
      ) as string;
      expect(dataJson).toContain('"user_agent":"unknown"');
    });

    it('should use "unknown" as default ipAddress and userAgent in logAdmin', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      await logger.logAdmin('admin.action', 1, 'entity', '1');

      const [, params] = vi.mocked(executor.execute).mock.calls[0]!;
      expect(params![2]).toBe('unknown');
      const dataJson = params!.find(
        (p) => typeof p === 'string' && p.includes('user_agent')
      ) as string;
      expect(dataJson).toContain('"user_agent":"unknown"');
    });

    it('should return false when dataError is set even if checksum would match', () => {
      const timestamp = '2026-02-13 12:00:00';
      const data = { status: 'success' };
      const userAgent = 'TestAgent/1.0';

      const envelope = { meta: { user_agent: userAgent, timestamp }, data };
      const dataJson = JSON.stringify(envelope);
      const checksum = computeTestChecksum(
        timestamp,
        42,
        '127.0.0.1',
        'test',
        'test',
        '1',
        dataJson
      );

      const result: AuditLogResult = {
        id: 1,
        timestamp: new Date('2026-02-13T12:00:00.000Z'),
        userId: 42,
        ipAddress: '127.0.0.1',
        action: 'test',
        entityType: 'test',
        entityId: '1',
        data,
        userAgent,
        dataError: 'intentional error flag',
        checksum,
      };

      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres');

      expect(logger.verify(result)).toBe(false);
    });

    it('should return null data and no dataError for empty data string', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockResolvedValue([
        {
          id: 1,
          timestamp: '2026-02-13 12:00:00',
          user_id: 1,
          ip_address: '127.0.0.1',
          action: 'test',
          entity_type: 'test',
          entity_id: '1',
          data_decrypted: '',
          checksum: 'a'.repeat(64),
        },
      ]);

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      const results = await logger.getLogsForEntity('test', 1);

      expect(results[0]!.data).toBeNull();
      expect(results[0]!.dataError).toBeNull();
    });

    it('should return null data and no dataError for null data string', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockResolvedValue([
        {
          id: 1,
          timestamp: '2026-02-13 12:00:00',
          user_id: 1,
          ip_address: '127.0.0.1',
          action: 'test',
          entity_type: 'test',
          entity_id: '1',
          data_decrypted: null,
          checksum: 'a'.repeat(64),
        },
      ]);

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      const results = await logger.getLogsForEntity('test', 1);

      expect(results[0]!.data).toBeNull();
      expect(results[0]!.dataError).toBeNull();
      expect(results[0]!.userAgent).toBe('unknown');
    });

    it('should return null data for JSON "null" string in data_decrypted', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockResolvedValue([
        {
          id: 1,
          timestamp: '2026-02-13 12:00:00',
          user_id: 1,
          ip_address: '127.0.0.1',
          action: 'test',
          entity_type: 'test',
          entity_id: '1',
          data_decrypted: 'null',
          checksum: 'a'.repeat(64),
        },
      ]);

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      const results = await logger.getLogsForEntity('test', 1);

      expect(results[0]!.data).toBeNull();
      expect(results[0]!.dataError).toBeNull();
    });

    it('should include WHERE entity_type in getLogsForEntity SQL', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      await logger.getLogsForEntity('user', 42);

      const [sql] = vi.mocked(executor.query).mock.calls[0]!;
      expect(sql).toMatch(/WHERE\s+entity_type/);
    });

    it('should include WHERE user_id in getLogsForUser SQL', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      await logger.getLogsForUser(42);

      const [sql] = vi.mocked(executor.query).mock.calls[0]!;
      expect(sql).toMatch(/WHERE\s+user_id/);
    });

    it('should preserve cause in StorageError on DB write failure', async () => {
      const dbError = new Error('DB connection failed');
      const executor = createMockExecutor();
      vi.mocked(executor.execute).mockRejectedValue(dbError);

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
        logFilePath: null,
      });

      try {
        await logger.log(new AuditLogEntry({ action: 'test', entityType: 'test', entityId: 1 }));
        expect.fail('should have thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(StorageError);
        expect((error as StorageError).cause).toBe(dbError);
      }
    });

    it('should preserve cause in StorageError when both DB and file fail', async () => {
      const dbError = new Error('DB down');
      const executor = createMockExecutor();
      vi.mocked(executor.execute).mockRejectedValue(dbError);

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
        logFilePath: '/dev/null/impossible/path/audit.log',
      });

      try {
        await logger.log(new AuditLogEntry({ action: 'test', entityType: 'test', entityId: 1 }));
        expect.fail('should have thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(StorageError);
        expect((error as StorageError).cause).toBe(dbError);
      }
    });

    it('should not include "File fallback also failed" when file write succeeds', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.execute).mockRejectedValue(new Error('DB down'));

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
        logFilePath: tempLogFile,
      });

      await expect(
        logger.log(new AuditLogEntry({ action: 'test', entityType: 'test', entityId: 1 }))
      ).rejects.toThrow(/Failed to write audit log to database/);

      await expect(
        logger.log(new AuditLogEntry({ action: 'test', entityType: 'test', entityId: 1 }))
      ).rejects.not.toThrow(/File fallback also failed/);
    });

    it('should preserve cause in StorageError on query failure', async () => {
      const queryError = new Error('Connection refused');
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockRejectedValue(queryError);

      const logger = new AuditLogger(executor, encryptionKey, 'postgres');

      try {
        await logger.getLogsForEntity('user', 1);
        expect.fail('should have thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(StorageError);
        expect((error as StorageError).cause).toBe(queryError);
      }
    });

    it('should preserve cause in StorageError on encodeData JSON failure', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      try {
        await logger.log(
          new AuditLogEntry({
            action: 'test',
            entityType: 'test',
            entityId: '1',
            data: { value: BigInt(42) } as unknown as Record<string, unknown>,
          })
        );
        expect.fail('should have thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(StorageError);
        expect((error as StorageError).cause).toBeDefined();
      }
    });

    it('should include decrypt_text in SQL for DB encryption queries', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      await logger.getLogsForEntity('user', 42);

      const [sql] = vi.mocked(executor.query).mock.calls[0]!;
      expect(sql).toContain('decrypt_text(data');
    });

    it('should NOT include decrypt_text in SQL for app encryption queries', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new AppEncryption(),
      });

      await logger.getLogsForEntity('user', 42);

      const [sql] = vi.mocked(executor.query).mock.calls[0]!;
      expect(sql).not.toContain('decrypt_text');
      // data column without decrypt_text wrapper
      expect(sql).toMatch(/,\s+data, checksum/s);
    });

    it('should not push dbEncryptionKey to params for app encryption queries', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new AppEncryption(),
      });

      await logger.getLogsForEntity('user', 42, 10);

      const [, params] = vi.mocked(executor.query).mock.calls[0]!;
      // For app encryption: params = [entityType, entityId, limit]
      expect(params).toHaveLength(3);
      expect(params).toEqual(['user', '42', 10]);
    });

    it('should push dbEncryptionKey as first param for DB encryption queries', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      await logger.getLogsForEntity('user', 42, 10);

      const [, params] = vi.mocked(executor.query).mock.calls[0]!;
      // For DB encryption: params = [dbEncryptionKey, entityType, entityId, limit]
      expect(params).toHaveLength(4);
      // First param is the derived hex key (64 hex chars)
      expect(params![0]).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should strip milliseconds from timestamp in formatTimestamp', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      await logger.log(new AuditLogEntry({ action: 'test', entityType: 'test', entityId: 1 }));

      const [, params] = vi.mocked(executor.execute).mock.calls[0]!;
      const timestamp = params![0] as string;
      // Must be in format "YYYY-MM-DD HH:MM:SS" without milliseconds or Z
      expect(timestamp).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);
    });

    it('should use ? placeholder for data column with app encryption INSERT', async () => {
      const mockEncryption: EncryptionInterface = {
        encrypt: vi.fn().mockReturnValue('encrypted-data'),
        decrypt: vi.fn(),
      };

      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'mysql', {
        encryption: mockEncryption,
      });

      await logger.log(new AuditLogEntry({ action: 'test', entityType: 'test', entityId: 1 }));

      const [sql] = vi.mocked(executor.execute).mock.calls[0]!;
      // VALUES should have 8 plain ? placeholders (no encrypt_text)
      expect(sql).not.toContain('encrypt_text');
      // The encrypted data param should be in the params
      const [, params] = vi.mocked(executor.execute).mock.calls[0]!;
      expect(params).toContain('encrypted-data');
    });

    it('should not remove non-stale lock file (exactly 60s old)', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
        logFilePath: tempLogFile,
      });

      const lockPath = `${tempLogFile}.lock`;
      writeFileSync(lockPath, '');
      // Set mtime to exactly 60 seconds ago (not stale - threshold is >= 60_000ms)
      const boundaryTime = new Date(Date.now() - 60_000);
      utimesSync(lockPath, boundaryTime, boundaryTime);

      // Lock is at exactly the threshold — should still be considered stale
      // The code uses >= so at exactly 60s, lock IS removed
      await logger.log(new AuditLogEntry({ action: 'test', entityType: 'test', entityId: 1 }));

      expect(existsSync(tempLogFile)).toBe(true);
    });

    it('should succeed despite 59-second-old lock file after successful db write', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
        logFilePath: tempLogFile,
      });

      const lockPath = `${tempLogFile}.lock`;
      writeFileSync(lockPath, '');
      const freshTime = new Date(Date.now() - 59_000);
      utimesSync(lockPath, freshTime, freshTime);

      // DB succeeds, file write fails due to non-stale lock — silently ignored
      await expect(
        logger.log(new AuditLogEntry({ action: 'test', entityType: 'test', entityId: 1 }))
      ).resolves.toBeUndefined();

      expect(executor.execute).toHaveBeenCalledOnce();
    });

    it('should correctly map ipAddress from database row', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockResolvedValue([
        {
          id: 1,
          timestamp: '2026-02-13 12:00:00',
          user_id: 1,
          ip_address: '192.168.42.99',
          action: 'test',
          entity_type: 'test',
          entity_id: '1',
          data_decrypted: null,
          checksum: 'a'.repeat(64),
        },
      ]);

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      const results = await logger.getLogsForEntity('test', 1);
      expect(results[0]!.ipAddress).toBe('192.168.42.99');
    });

    it('should correctly map checksum from database row', async () => {
      const checksum = 'b'.repeat(64);
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockResolvedValue([
        {
          id: 1,
          timestamp: '2026-02-13 12:00:00',
          user_id: 1,
          ip_address: '127.0.0.1',
          action: 'test',
          entity_type: 'test',
          entity_id: '1',
          data_decrypted: null,
          checksum,
        },
      ]);

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      const results = await logger.getLogsForEntity('test', 1);
      expect(results[0]!.checksum).toBe(checksum);
    });

    it('should reject checksum with extra characters (65 hex chars)', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockResolvedValue([
        {
          id: 1,
          timestamp: '2026-02-13 12:00:00',
          user_id: 1,
          ip_address: '127.0.0.1',
          action: 'test',
          entity_type: 'test',
          entity_id: '1',
          data_decrypted: null,
          checksum: 'a'.repeat(65),
        },
      ]);

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      await expect(logger.getLogsForEntity('test', 1)).rejects.toThrow(
        'Invalid type for field "checksum"'
      );
    });

    it('should reject checksum with prefix before 64 hex chars', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockResolvedValue([
        {
          id: 1,
          timestamp: '2026-02-13 12:00:00',
          user_id: 1,
          ip_address: '127.0.0.1',
          action: 'test',
          entity_type: 'test',
          entity_id: '1',
          data_decrypted: null,
          checksum: 'x' + 'a'.repeat(64),
        },
      ]);

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      await expect(logger.getLogsForEntity('test', 1)).rejects.toThrow(
        'Invalid type for field "checksum"'
      );
    });

    it('should accept checksum of exactly 64 hex characters', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockResolvedValue([
        {
          id: 1,
          timestamp: '2026-02-13 12:00:00',
          user_id: 1,
          ip_address: '127.0.0.1',
          action: 'test',
          entity_type: 'test',
          entity_id: '1',
          data_decrypted: null,
          checksum: 'abcdef0123456789'.repeat(4),
        },
      ]);

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      const results = await logger.getLogsForEntity('test', 1);
      expect(results[0]!.checksum).toBe('abcdef0123456789'.repeat(4));
    });

    it('should produce correct $1, $2, $3 parameter ordering for postgres', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      await logger.getLogsForEntity('user', 42, 25);

      const [sql] = vi.mocked(executor.query).mock.calls[0]!;
      // Should contain $1, $2, $3, $4 in ascending order
      expect(sql).toContain('$1');
      expect(sql).toContain('$2');
      expect(sql).toContain('$3');
      expect(sql).toContain('$4');
      // Verify ordering: $1 comes before $2, $2 before $3, etc.
      const idx1 = sql.indexOf('$1');
      const idx2 = sql.indexOf('$2');
      const idx3 = sql.indexOf('$3');
      const idx4 = sql.indexOf('$4');
      expect(idx1).toBeLessThan(idx2);
      expect(idx2).toBeLessThan(idx3);
      expect(idx3).toBeLessThan(idx4);
    });

    it('should reject non-string checksum in validateRowSchema (number)', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockResolvedValue([
        {
          id: 1,
          timestamp: '2026-02-13 12:00:00',
          user_id: 1,
          ip_address: '127.0.0.1',
          action: 'test',
          entity_type: 'test',
          entity_id: '1',
          data_decrypted: null,
          checksum: 12345,
        },
      ]);

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      await expect(logger.getLogsForEntity('test', 1)).rejects.toThrow(
        'Invalid type for field "checksum"'
      );
    });

    it('should include exact field names in missing fields error', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockResolvedValue([
        {
          id: 1,
          timestamp: '2026-02-13 12:00:00',
          // missing: user_id, ip_address, action, entity_type, entity_id, checksum
        },
      ]);

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      await expect(logger.getLogsForEntity('test', 1)).rejects.toThrow(
        'Missing required fields in database row: user_id, ip_address, action, entity_type, entity_id, checksum'
      );
    });

    it('should throw for boolean id type in validateRowSchema', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockResolvedValue([
        {
          id: true,
          timestamp: '2026-02-13 12:00:00',
          user_id: 1,
          ip_address: '127.0.0.1',
          action: 'test',
          entity_type: 'test',
          entity_id: '1',
          data_decrypted: null,
          checksum: 'a'.repeat(64),
        },
      ]);

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      await expect(logger.getLogsForEntity('test', 1)).rejects.toThrow(
        'Invalid type for field "id" in database row'
      );
    });

    it('should accept string id type', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockResolvedValue([
        {
          id: 'uuid-string',
          timestamp: '2026-02-13 12:00:00',
          user_id: 1,
          ip_address: '127.0.0.1',
          action: 'test',
          entity_type: 'test',
          entity_id: '1',
          data_decrypted: null,
          checksum: 'a'.repeat(64),
        },
      ]);

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      const results = await logger.getLogsForEntity('test', 1);
      expect(results[0]!.id).toBeNaN(); // Number('uuid-string') is NaN
    });

    it('should throw for number timestamp type', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockResolvedValue([
        {
          id: 1,
          timestamp: 12345,
          user_id: 1,
          ip_address: '127.0.0.1',
          action: 'test',
          entity_type: 'test',
          entity_id: '1',
          data_decrypted: null,
          checksum: 'a'.repeat(64),
        },
      ]);

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      await expect(logger.getLogsForEntity('test', 1)).rejects.toThrow(
        'Invalid type for field "timestamp" in database row'
      );
    });

    it('should accept Date timestamp type', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockResolvedValue([
        {
          id: 1,
          timestamp: new Date('2026-02-13T12:00:00.000Z'),
          user_id: 1,
          ip_address: '127.0.0.1',
          action: 'test',
          entity_type: 'test',
          entity_id: '1',
          data_decrypted: null,
          checksum: 'a'.repeat(64),
        },
      ]);

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      const results = await logger.getLogsForEntity('test', 1);
      expect(results[0]!.timestamp).toBeInstanceOf(Date);
    });

    it('should handle non-object envelope without meta', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockResolvedValue([
        {
          id: 1,
          timestamp: '2026-02-13 12:00:00',
          user_id: 1,
          ip_address: '127.0.0.1',
          action: 'test',
          entity_type: 'test',
          entity_id: '1',
          data_decrypted: JSON.stringify({ no_meta: true }),
          checksum: 'a'.repeat(64),
        },
      ]);

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      const results = await logger.getLogsForEntity('test', 1);
      expect(results[0]!.userAgent).toBe('unknown');
    });

    it('should return EEXIST error when lock file already exists', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
        logFilePath: tempLogFile,
      });

      writeFileSync(`${tempLogFile}.lock`, '');

      try {
        await logger.log(new AuditLogEntry({ action: 'test', entityType: 'test', entityId: 1 }));
        expect.fail('should have thrown');
      } catch (error) {
        // Should be the original EEXIST error, not a TypeError from lockHandle.close()
        expect(error).not.toBeInstanceOf(TypeError);
      }
    });

    it('should accept limit at exactly maxLimit boundary', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', { maxLimit: 100 });

      await logger.getLogsForEntity('user', 1, 100);
      expect(executor.query).toHaveBeenCalledOnce();
    });

    it('should reject limit one above maxLimit', async () => {
      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', { maxLimit: 100 });

      await expect(logger.getLogsForEntity('user', 1, 101)).rejects.toThrow(
        'Limit must not exceed 100'
      );
    });

    it('should include ? placeholder in VALUES for app encryption data', async () => {
      const mockEncryption: EncryptionInterface = {
        encrypt: vi.fn().mockReturnValue('encrypted-data'),
        decrypt: vi.fn(),
      };

      const executor = createMockExecutor();
      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: mockEncryption,
      });

      await logger.log(new AuditLogEntry({ action: 'test', entityType: 'test', entityId: 1 }));

      const [sql] = vi.mocked(executor.execute).mock.calls[0]!;
      // The VALUES clause should have exactly 8 placeholders for postgres ($1-$8)
      // Count $ placeholders — all should be present
      const placeholders = sql.match(/\$\d+/g);
      expect(placeholders).toHaveLength(8);
    });

    it('should treat lock at exactly LOCK_STALE_MS as stale (fake timers)', async () => {
      vi.useFakeTimers();
      vi.setSystemTime(1_000_000);

      try {
        const executor = createMockExecutor();
        const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
          encryption: new DatabaseEncryption(),
          logFilePath: tempLogFile,
        });

        const lockPath = `${tempLogFile}.lock`;
        writeFileSync(lockPath, '');
        // Set mtime to exactly LOCK_STALE_MS (60_000ms) ago
        const staleTime = new Date(1_000_000 - 60_000);
        utimesSync(lockPath, staleTime, staleTime);

        // With >=: 60_000 >= 60_000 = true → stale → removed → write succeeds
        // With >: 60_000 > 60_000 = false → not stale → EEXIST
        await logger.log(new AuditLogEntry({ action: 'test', entityType: 'test', entityId: 1 }));

        expect(existsSync(tempLogFile)).toBe(true);
      } finally {
        vi.useRealTimers();
      }
    });

    it('should reject non-string checksum whose string coercion matches hex pattern', async () => {
      const executor = createMockExecutor();
      vi.mocked(executor.query).mockResolvedValue([
        {
          id: 1,
          timestamp: '2026-02-13 12:00:00',
          user_id: 1,
          ip_address: '127.0.0.1',
          action: 'test',
          entity_type: 'test',
          entity_id: '1',
          data_decrypted: null,
          checksum: { toString: () => 'a'.repeat(64) },
        },
      ]);

      const logger = new AuditLogger(executor, encryptionKey, 'postgres', {
        encryption: new DatabaseEncryption(),
      });

      await expect(logger.getLogsForEntity('test', 1)).rejects.toThrow(
        'Invalid type for field "checksum"'
      );
    });
  });
});
