import { describe, it, expect } from 'vitest';
import { AuditLogError } from '../../src/exceptions/AuditLogError.js';
import { EncryptionError } from '../../src/exceptions/EncryptionError.js';
import { StorageError } from '../../src/exceptions/StorageError.js';

describe('AuditLogError', () => {
  it('should be an instance of Error', () => {
    const error = new AuditLogError('test');
    expect(error).toBeInstanceOf(Error);
    expect(error).toBeInstanceOf(AuditLogError);
  });

  it('should have correct name', () => {
    const error = new AuditLogError('test');
    expect(error.name).toBe('AuditLogError');
  });

  it('should have correct message', () => {
    const error = new AuditLogError('Something went wrong');
    expect(error.message).toBe('Something went wrong');
  });

  it('should support cause option', () => {
    const cause = new Error('original');
    const error = new AuditLogError('wrapped', { cause });
    expect(error.cause).toBe(cause);
  });
});

describe('EncryptionError', () => {
  it('should extend AuditLogError', () => {
    const error = new EncryptionError('test');
    expect(error).toBeInstanceOf(AuditLogError);
    expect(error).toBeInstanceOf(Error);
  });

  it('should have correct name', () => {
    const error = new EncryptionError('test');
    expect(error.name).toBe('EncryptionError');
  });

  it('should support cause option', () => {
    const cause = new Error('original');
    const error = new EncryptionError('wrapped', { cause });
    expect(error.cause).toBe(cause);
  });
});

describe('StorageError', () => {
  it('should extend AuditLogError', () => {
    const error = new StorageError('test');
    expect(error).toBeInstanceOf(AuditLogError);
    expect(error).toBeInstanceOf(Error);
  });

  it('should have correct name', () => {
    const error = new StorageError('test');
    expect(error.name).toBe('StorageError');
  });

  it('should support cause option', () => {
    const cause = new Error('original');
    const error = new StorageError('wrapped', { cause });
    expect(error.cause).toBe(cause);
  });
});
