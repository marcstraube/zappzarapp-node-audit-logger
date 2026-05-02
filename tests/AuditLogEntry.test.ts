import { describe, expect, it } from 'vitest';
import { AuditLogEntry } from '../src/AuditLogEntry.js';
import { AuditLogError } from '../src/exceptions/AuditLogError.js';

describe('AuditLogEntry', () => {
  it('should create a valid entry with all fields', () => {
    const entry = new AuditLogEntry({
      action: 'user.login',
      entityType: 'user',
      entityId: 42,
      userId: 1,
      ipAddress: '127.0.0.1',
      userAgent: 'Test/1.0',
      data: { key: 'value' },
    });

    expect(entry.action).toBe('user.login');
    expect(entry.entityType).toBe('user');
    expect(entry.entityId).toBe(42);
    expect(entry.userId).toBe(1);
    expect(entry.ipAddress).toBe('127.0.0.1');
    expect(entry.userAgent).toBe('Test/1.0');
    expect(entry.data).toEqual({ key: 'value' });
  });

  it('should use defaults for optional fields', () => {
    const entry = new AuditLogEntry({
      action: 'test',
      entityType: 'test',
      entityId: '1',
    });

    expect(entry.userId).toBeNull();
    expect(entry.ipAddress).toBe('unknown');
    expect(entry.userAgent).toBe('unknown');
    expect(entry.data).toEqual({});
  });

  it('should accept string entityId', () => {
    const entry = new AuditLogEntry({
      action: 'document.view',
      entityType: 'document',
      entityId: 'doc-uuid-12345',
    });

    expect(entry.entityId).toBe('doc-uuid-12345');
  });

  it('should accept empty data object', () => {
    const entry = new AuditLogEntry({
      action: 'test',
      entityType: 'test',
      entityId: '1',
      data: {},
    });

    expect(entry.data).toEqual({});
  });

  it('should accept complex nested data', () => {
    const complexData = {
      before: { name: 'Alice', email: 'alice@example.com' },
      after: { name: 'Alice B.', email: 'alice@example.com' },
      changes: ['name'],
      metadata: { version: 2, nested: { deep: true } },
    };

    const entry = new AuditLogEntry({
      action: 'user.update',
      entityType: 'user',
      entityId: 42,
      data: complexData,
    });

    expect(entry.data).toEqual(complexData);
  });

  it('should accept different IP formats', () => {
    // IPv4
    const entry4 = new AuditLogEntry({
      action: 'test',
      entityType: 'test',
      entityId: '1',
      ipAddress: '192.168.1.1',
    });
    expect(entry4.ipAddress).toBe('192.168.1.1');

    // IPv6
    const entry6 = new AuditLogEntry({
      action: 'test',
      entityType: 'test',
      entityId: '1',
      ipAddress: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
    });
    expect(entry6.ipAddress).toBe('2001:0db8:85a3:0000:0000:8a2e:0370:7334');
  });

  it('should accept all max-length values simultaneously', () => {
    expect(
      () =>
        new AuditLogEntry({
          action: 'x'.repeat(255),
          entityType: 'x'.repeat(100),
          entityId: 'x'.repeat(255),
          ipAddress: 'x'.repeat(45),
          userAgent: 'x'.repeat(500),
        })
    ).not.toThrow();
  });

  describe('byte-length validation', () => {
    it('should validate byte length not character count for multi-byte characters', () => {
      // 'ä' is 2 bytes in UTF-8, so 128 * 'ä' = 256 bytes but only 128 characters
      expect(
        () => new AuditLogEntry({ action: 'ä'.repeat(128), entityType: 'test', entityId: '1' })
      ).toThrow('Action must not exceed 255 bytes');
    });

    it('should accept multi-byte action within byte limit', () => {
      // 127 * 'ä' = 254 bytes — within 255 byte limit
      expect(
        () => new AuditLogEntry({ action: 'ä'.repeat(127), entityType: 'test', entityId: '1' })
      ).not.toThrow();
    });
  });

  describe('action validation', () => {
    it('should throw AuditLogError for empty action', () => {
      expect(() => new AuditLogEntry({ action: '', entityType: 'test', entityId: '1' })).toThrow(
        AuditLogError
      );
      expect(() => new AuditLogEntry({ action: '', entityType: 'test', entityId: '1' })).toThrow(
        'Action must not be empty'
      );
    });

    it('should throw AuditLogError for action exceeding 255 bytes', () => {
      expect(
        () => new AuditLogEntry({ action: 'x'.repeat(256), entityType: 'test', entityId: '1' })
      ).toThrow(AuditLogError);
      expect(
        () => new AuditLogEntry({ action: 'x'.repeat(256), entityType: 'test', entityId: '1' })
      ).toThrow('Action must not exceed 255 bytes');
    });

    it('should accept action at exactly 255 bytes', () => {
      expect(
        () => new AuditLogEntry({ action: 'x'.repeat(255), entityType: 'test', entityId: '1' })
      ).not.toThrow();
    });
  });

  describe('entityType validation', () => {
    it('should throw AuditLogError for empty entityType', () => {
      expect(() => new AuditLogEntry({ action: 'test', entityType: '', entityId: '1' })).toThrow(
        AuditLogError
      );
      expect(() => new AuditLogEntry({ action: 'test', entityType: '', entityId: '1' })).toThrow(
        'Entity type must not be empty'
      );
    });

    it('should throw AuditLogError for entityType exceeding 100 bytes', () => {
      expect(
        () => new AuditLogEntry({ action: 'test', entityType: 'x'.repeat(101), entityId: '1' })
      ).toThrow(AuditLogError);
      expect(
        () => new AuditLogEntry({ action: 'test', entityType: 'x'.repeat(101), entityId: '1' })
      ).toThrow('Entity type must not exceed 100 bytes');
    });

    it('should accept entityType at exactly 100 bytes', () => {
      expect(
        () => new AuditLogEntry({ action: 'test', entityType: 'x'.repeat(100), entityId: '1' })
      ).not.toThrow();
    });
  });

  describe('entityId validation', () => {
    it('should throw AuditLogError for empty entityId', () => {
      expect(() => new AuditLogEntry({ action: 'test', entityType: 'test', entityId: '' })).toThrow(
        AuditLogError
      );
      expect(() => new AuditLogEntry({ action: 'test', entityType: 'test', entityId: '' })).toThrow(
        'Entity ID must not be empty'
      );
    });

    it('should throw AuditLogError for entityId exceeding 255 bytes', () => {
      expect(
        () => new AuditLogEntry({ action: 'test', entityType: 'test', entityId: 'x'.repeat(256) })
      ).toThrow(AuditLogError);
      expect(
        () => new AuditLogEntry({ action: 'test', entityType: 'test', entityId: 'x'.repeat(256) })
      ).toThrow('Entity ID must not exceed 255 bytes');
    });

    it('should accept numeric entityId', () => {
      const entry = new AuditLogEntry({ action: 'test', entityType: 'test', entityId: 42 });
      expect(entry.entityId).toBe(42);
    });
  });

  describe('ipAddress validation', () => {
    it('should throw AuditLogError for ipAddress exceeding 45 bytes', () => {
      expect(
        () =>
          new AuditLogEntry({
            action: 'test',
            entityType: 'test',
            entityId: '1',
            ipAddress: 'x'.repeat(46),
          })
      ).toThrow(AuditLogError);
      expect(
        () =>
          new AuditLogEntry({
            action: 'test',
            entityType: 'test',
            entityId: '1',
            ipAddress: 'x'.repeat(46),
          })
      ).toThrow('IP address must not exceed 45 bytes');
    });

    it('should accept ipAddress at exactly 45 bytes', () => {
      expect(
        () =>
          new AuditLogEntry({
            action: 'test',
            entityType: 'test',
            entityId: '1',
            ipAddress: 'x'.repeat(45),
          })
      ).not.toThrow();
    });
  });

  describe('userAgent validation', () => {
    it('should throw AuditLogError for userAgent exceeding 500 bytes', () => {
      expect(
        () =>
          new AuditLogEntry({
            action: 'test',
            entityType: 'test',
            entityId: '1',
            userAgent: 'x'.repeat(501),
          })
      ).toThrow(AuditLogError);
      expect(
        () =>
          new AuditLogEntry({
            action: 'test',
            entityType: 'test',
            entityId: '1',
            userAgent: 'x'.repeat(501),
          })
      ).toThrow('User agent must not exceed 500 bytes');
    });

    it('should accept userAgent at exactly 500 bytes', () => {
      expect(
        () =>
          new AuditLogEntry({
            action: 'test',
            entityType: 'test',
            entityId: '1',
            userAgent: 'x'.repeat(500),
          })
      ).not.toThrow();
    });
  });
});
