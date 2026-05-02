import { describe, it, expect } from 'vitest';
import type { AuditLogResult } from '../src/AuditLogResult.js';

describe('AuditLogResult', () => {
  // Helper to create a valid result
  function createResult(overrides: Partial<AuditLogResult> = {}): AuditLogResult {
    return {
      id: 1,
      timestamp: new Date('2026-02-13T12:00:00.000Z'),
      userId: 42,
      ipAddress: '127.0.0.1',
      action: 'user.login',
      entityType: 'user',
      entityId: '42',
      data: { status: 'success' },
      userAgent: 'TestAgent/1.0',
      dataError: null,
      checksum: 'abc123def456',
      ...overrides,
    };
  }

  it('should hold all fields correctly when fully populated', () => {
    const result = createResult();

    expect(result.id).toBe(1);
    expect(result.timestamp).toEqual(new Date('2026-02-13T12:00:00.000Z'));
    expect(result.userId).toBe(42);
    expect(result.ipAddress).toBe('127.0.0.1');
    expect(result.action).toBe('user.login');
    expect(result.entityType).toBe('user');
    expect(result.entityId).toBe('42');
    expect(result.data).toEqual({ status: 'success' });
    expect(result.userAgent).toBe('TestAgent/1.0');
    expect(result.dataError).toBeNull();
    expect(result.checksum).toBe('abc123def456');
  });

  it('should allow null userId', () => {
    const result = createResult({ userId: null });
    expect(result.userId).toBeNull();
  });

  it('should allow null data', () => {
    const result = createResult({ data: null });
    expect(result.data).toBeNull();
  });

  it('should allow empty data object', () => {
    const result = createResult({ data: {} });
    expect(result.data).toEqual({});
  });

  it('should preserve complex nested data', () => {
    const complexData = {
      user: { name: 'John', roles: ['admin', 'user'] },
      meta: { version: 2, nested: { deep: true } },
    };
    const result = createResult({ data: complexData });
    expect(result.data).toEqual(complexData);
  });

  it('should preserve timestamp as Date object', () => {
    const ts = new Date('2026-06-15T08:30:00.000Z');
    const result = createResult({ timestamp: ts });
    expect(result.timestamp).toBe(ts);
    expect(result.timestamp.toISOString()).toBe('2026-06-15T08:30:00.000Z');
  });

  it('should hold entityId as string', () => {
    const result = createResult({ entityId: '99' });
    expect(result.entityId).toBe('99');
    expect(typeof result.entityId).toBe('string');
  });

  it('should hold checksum as string', () => {
    const result = createResult({ checksum: 'a'.repeat(64) });
    expect(result.checksum).toBe('a'.repeat(64));
    expect(typeof result.checksum).toBe('string');
  });

  it('should default dataError to null when not set', () => {
    const result = createResult();
    expect(result.dataError).toBeNull();
  });

  it('should preserve dataError when set', () => {
    const result = createResult({ dataError: 'Corrupted JSON data: Unexpected token' });
    expect(result.dataError).toBe('Corrupted JSON data: Unexpected token');
    expect(result.data).toEqual({ status: 'success' });
  });

  it('should handle IPv4 addresses', () => {
    const result = createResult({ ipAddress: '192.168.1.1' });
    expect(result.ipAddress).toBe('192.168.1.1');
  });

  it('should handle IPv6 addresses', () => {
    const result = createResult({ ipAddress: '2001:0db8:85a3:0000:0000:8a2e:0370:7334' });
    expect(result.ipAddress).toBe('2001:0db8:85a3:0000:0000:8a2e:0370:7334');
  });

  it('should handle IPv4-mapped IPv6 addresses', () => {
    const result = createResult({ ipAddress: '::ffff:192.168.1.1' });
    expect(result.ipAddress).toBe('::ffff:192.168.1.1');
  });

  it('should hold numeric id', () => {
    const result = createResult({ id: 999 });
    expect(result.id).toBe(999);
    expect(typeof result.id).toBe('number');
  });
});
