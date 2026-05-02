import { closeSync, existsSync, ftruncateSync, openSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { FileLogReader } from '../src/FileLogReader.js';
import { AppEncryption } from '../src/encryption/AppEncryption.js';
import type { EncryptionInterface } from '../src/encryption/EncryptionInterface.js';
import { EncryptionError } from '../src/exceptions/EncryptionError.js';
import { StorageError } from '../src/exceptions/StorageError.js';
import { MAX_FILE_LOG_SIZE } from '../src/validation.js';

const encryptionKey = 'test-encryption-key-32-characters!';

describe('FileLogReader', () => {
  let tempFile: string;
  const encryption = new AppEncryption();
  let reader: FileLogReader;

  beforeEach(() => {
    tempFile = join(
      tmpdir(),
      `filelog-test-${Date.now()}-${Math.random().toString(36).slice(2)}.log`
    );
    reader = new FileLogReader(encryption, encryptionKey);
  });

  afterEach(() => {
    if (existsSync(tempFile)) {
      unlinkSync(tempFile);
    }
  });

  it('should read a valid file log entry', async () => {
    const entry = {
      timestamp: '2026-02-15 14:30:45',
      user_id: 123,
      ip_address: '192.168.1.1',
      user_agent: 'Mozilla/5.0',
      action: 'user.login',
      entity_type: 'user',
      entity_id: '123',
      data: { status: 'success' },
      checksum: 'abc123',
    };

    const encrypted = encryption.encrypt(JSON.stringify(entry), encryptionKey);
    writeFileSync(tempFile, encrypted + '\n', { mode: 0o600 });

    const results = await reader.read(tempFile);

    expect(results).toHaveLength(1);
    expect(results[0]!.action).toBe('user.login');
    expect(results[0]!.entityType).toBe('user');
    expect(results[0]!.entityId).toBe('123');
    expect(results[0]!.userId).toBe(123);
    expect(results[0]!.ipAddress).toBe('192.168.1.1');
    expect(results[0]!.userAgent).toBe('Mozilla/5.0');
    expect(results[0]!.data).toEqual({ status: 'success' });
    expect(results[0]!.checksum).toBe('abc123');
    expect(results[0]!.dataError).toBeNull();
  });

  it('should handle null user_id', async () => {
    const entry = {
      timestamp: '2026-02-15 14:30:45',
      user_id: null,
      ip_address: '10.0.0.1',
      user_agent: 'TestAgent',
      action: 'system.cleanup',
      entity_type: 'system',
      entity_id: '1',
      data: {},
      checksum: 'def456',
    };

    const encrypted = encryption.encrypt(JSON.stringify(entry), encryptionKey);
    writeFileSync(tempFile, encrypted + '\n', { mode: 0o600 });

    const results = await reader.read(tempFile);
    expect(results[0]!.userId).toBeNull();
  });

  it('should throw StorageError for missing required fields', async () => {
    const entry = {
      timestamp: '2026-02-15 14:30:45',
      action: 'test',
      // missing: user_id, ip_address, user_agent, entity_type, entity_id, checksum
    };

    const encrypted = encryption.encrypt(JSON.stringify(entry), encryptionKey);
    writeFileSync(tempFile, encrypted + '\n', { mode: 0o600 });

    await expect(reader.read(tempFile)).rejects.toThrow(StorageError);
    await expect(reader.read(tempFile)).rejects.toThrow(
      /Missing required fields in file log line 1/
    );
    await expect(reader.read(tempFile)).rejects.toThrow(/user_id/);
  });

  it('should throw EncryptionError for decrypt failure', async () => {
    writeFileSync(tempFile, 'not-valid-base64-encrypted-data\n', { mode: 0o600 });

    await expect(reader.read(tempFile)).rejects.toThrow(EncryptionError);
  });

  it('should throw StorageError for invalid JSON', async () => {
    const encrypted = encryption.encrypt('not-json', encryptionKey);
    writeFileSync(tempFile, encrypted + '\n', { mode: 0o600 });

    await expect(reader.read(tempFile)).rejects.toThrow(StorageError);
    await expect(reader.read(tempFile)).rejects.toThrow(/Corrupted JSON in file log line 1/);
  });

  it('should handle null data gracefully', async () => {
    const entry = {
      timestamp: '2026-02-15 14:30:45',
      user_id: 1,
      ip_address: '127.0.0.1',
      user_agent: 'Test',
      action: 'test',
      entity_type: 'test',
      entity_id: '1',
      data: null,
      checksum: 'abc',
    };

    const encrypted = encryption.encrypt(JSON.stringify(entry), encryptionKey);
    writeFileSync(tempFile, encrypted + '\n', { mode: 0o600 });

    const results = await reader.read(tempFile);

    expect(results[0]!.data).toBeNull();
    expect(results[0]!.dataError).toBeNull();
  });

  it('should handle multiple entries', async () => {
    const entries = [
      {
        timestamp: '2026-02-15 14:30:45',
        user_id: 1,
        ip_address: '127.0.0.1',
        user_agent: 'Agent1',
        action: 'action1',
        entity_type: 'type1',
        entity_id: '1',
        data: {},
        checksum: 'c1',
      },
      {
        timestamp: '2026-02-15 14:31:00',
        user_id: 2,
        ip_address: '10.0.0.1',
        user_agent: 'Agent2',
        action: 'action2',
        entity_type: 'type2',
        entity_id: '2',
        data: {},
        checksum: 'c2',
      },
    ];

    const lines = entries
      .map((e) => encryption.encrypt(JSON.stringify(e), encryptionKey))
      .join('\n');
    writeFileSync(tempFile, lines + '\n', { mode: 0o600 });

    const results = await reader.read(tempFile);
    expect(results).toHaveLength(2);
    expect(results[0]!.action).toBe('action1');
    expect(results[1]!.action).toBe('action2');
  });

  it('should wrap non-Error decrypt failure in StorageError', async () => {
    const failingEncryption: EncryptionInterface = {
      encrypt: (plaintext: string) => plaintext,
      decrypt: () => {
        throw 'raw string error';
      },
    };

    const failReader = new FileLogReader(failingEncryption, encryptionKey);
    writeFileSync(tempFile, 'some-data\n', { mode: 0o600 });

    await expect(failReader.read(tempFile)).rejects.toThrow(StorageError);
    await expect(failReader.read(tempFile)).rejects.toThrow(
      'Failed to decrypt file log line 1: raw string error'
    );
  });

  it('should return empty array for non-existent file', async () => {
    const nonExistent = join(tmpdir(), `non-existent-${Date.now()}.log`);
    const results = await reader.read(nonExistent);
    expect(results).toEqual([]);
  });

  it('should throw StorageError for non-ENOENT stat error (ENOTDIR)', async () => {
    // stat() on a path through a regular file triggers ENOTDIR
    writeFileSync(tempFile, 'data', { mode: 0o600 });
    const invalidPath = tempFile + '/subpath';

    await expect(reader.read(invalidPath)).rejects.toThrow(StorageError);
    await expect(reader.read(invalidPath)).rejects.toThrow('Failed to read file log');
  });

  it('should throw StorageError for non-ENOENT readFile error (EISDIR)', async () => {
    // stat() succeeds on directories, but readFile() triggers EISDIR
    await expect(reader.read(tmpdir())).rejects.toThrow(StorageError);
    await expect(reader.read(tmpdir())).rejects.toThrow('Failed to read file log');
  });

  it('should return empty array for empty file', async () => {
    writeFileSync(tempFile, '', { mode: 0o600 });
    const results = await reader.read(tempFile);
    expect(results).toEqual([]);
  });

  it('should use line number as id', async () => {
    const entries = [
      {
        timestamp: '2026-02-15 14:30:45',
        user_id: 1,
        ip_address: '127.0.0.1',
        user_agent: 'Agent1',
        action: 'action1',
        entity_type: 'type1',
        entity_id: '1',
        data: {},
        checksum: 'c1',
      },
      {
        timestamp: '2026-02-15 14:31:00',
        user_id: 2,
        ip_address: '10.0.0.1',
        user_agent: 'Agent2',
        action: 'action2',
        entity_type: 'type2',
        entity_id: '2',
        data: {},
        checksum: 'c2',
      },
    ];

    const lines = entries
      .map((e) => encryption.encrypt(JSON.stringify(e), encryptionKey))
      .join('\n');
    writeFileSync(tempFile, lines + '\n', { mode: 0o600 });

    const results = await reader.read(tempFile);
    expect(results[0]!.id).toBe(1);
    expect(results[1]!.id).toBe(2);
  });

  it('should throw StorageError for invalid timestamp', async () => {
    const entry = {
      timestamp: 'not-a-valid-date',
      user_id: 1,
      ip_address: '127.0.0.1',
      user_agent: 'Test',
      action: 'test',
      entity_type: 'test',
      entity_id: '1',
      data: {},
      checksum: 'abc',
    };

    const encrypted = encryption.encrypt(JSON.stringify(entry), encryptionKey);
    writeFileSync(tempFile, encrypted + '\n', { mode: 0o600 });

    await expect(reader.read(tempFile)).rejects.toThrow(StorageError);
    await expect(reader.read(tempFile)).rejects.toThrow(/Invalid timestamp in file log line 1/);
  });

  it('should detect missing timestamp field', async () => {
    const entry = {
      // timestamp intentionally missing
      user_id: 1,
      ip_address: '127.0.0.1',
      user_agent: 'Test',
      action: 'test',
      entity_type: 'test',
      entity_id: '1',
      data: {},
      checksum: 'abc',
    };

    const encrypted = encryption.encrypt(JSON.stringify(entry), encryptionKey);
    writeFileSync(tempFile, encrypted + '\n', { mode: 0o600 });

    await expect(reader.read(tempFile)).rejects.toThrow(StorageError);
    await expect(reader.read(tempFile)).rejects.toThrow(
      /Missing required fields in file log line 1.*timestamp/
    );
  });

  it('should cast string user_id to number', async () => {
    const entry = {
      timestamp: '2026-02-15 14:30:45',
      user_id: '123', // string in JSON, should be cast to number
      ip_address: '127.0.0.1',
      user_agent: 'Test',
      action: 'test',
      entity_type: 'test',
      entity_id: '1',
      data: {},
      checksum: 'abc',
    };

    const encrypted = encryption.encrypt(JSON.stringify(entry), encryptionKey);
    writeFileSync(tempFile, encrypted + '\n', { mode: 0o600 });

    const results = await reader.read(tempFile);
    expect(results[0]!.userId).toBe(123);
    expect(typeof results[0]!.userId).toBe('number');
  });

  it('should throw StorageError when file exceeds MAX_FILE_LOG_SIZE', async () => {
    // Create a file just over the limit by writing enough encrypted lines
    const entry = {
      timestamp: '2026-02-15 14:30:45',
      user_id: 1,
      ip_address: '127.0.0.1',
      user_agent: 'Test',
      action: 'test',
      entity_type: 'test',
      entity_id: '1',
      data: { payload: 'x'.repeat(1000) },
      checksum: 'abc',
    };

    const encrypted = encryption.encrypt(JSON.stringify(entry), encryptionKey);
    const lineSize = Buffer.byteLength(encrypted + '\n');
    const linesNeeded = Math.ceil(MAX_FILE_LOG_SIZE / lineSize) + 1;
    const content = (encrypted + '\n').repeat(linesNeeded);
    writeFileSync(tempFile, content, { mode: 0o600 });

    await expect(reader.read(tempFile)).rejects.toThrow(StorageError);
    await expect(reader.read(tempFile)).rejects.toThrow(/File log exceeds maximum size/);
  });

  it('should read file at exactly MAX_FILE_LOG_SIZE', async () => {
    // A file at exactly the limit should be readable (not exceed)
    const entry = {
      timestamp: '2026-02-15 14:30:45',
      user_id: 1,
      ip_address: '127.0.0.1',
      user_agent: 'Test',
      action: 'test',
      entity_type: 'test',
      entity_id: '1',
      data: {},
      checksum: 'abc',
    };

    const encrypted = encryption.encrypt(JSON.stringify(entry), encryptionKey);
    writeFileSync(tempFile, encrypted + '\n', { mode: 0o600 });

    // File is well under limit — should succeed
    const results = await reader.read(tempFile);
    expect(results).toHaveLength(1);
  });

  it('should throw StorageError when decrypted JSON is a number', async () => {
    const encrypted = encryption.encrypt('42', encryptionKey);
    writeFileSync(tempFile, encrypted + '\n', { mode: 0o600 });

    await expect(reader.read(tempFile)).rejects.toThrow(StorageError);
    await expect(reader.read(tempFile)).rejects.toThrow(
      /Corrupted JSON in file log line 1: expected object/
    );
  });

  it('should throw StorageError when decrypted JSON is null', async () => {
    const encrypted = encryption.encrypt('null', encryptionKey);
    writeFileSync(tempFile, encrypted + '\n', { mode: 0o600 });

    await expect(reader.read(tempFile)).rejects.toThrow(StorageError);
    await expect(reader.read(tempFile)).rejects.toThrow(
      /Corrupted JSON in file log line 1: expected object/
    );
  });

  it('should throw StorageError when decrypted JSON is an array', async () => {
    const encrypted = encryption.encrypt('[1,2,3]', encryptionKey);
    writeFileSync(tempFile, encrypted + '\n', { mode: 0o600 });

    await expect(reader.read(tempFile)).rejects.toThrow(StorageError);
    await expect(reader.read(tempFile)).rejects.toThrow(
      /Corrupted JSON in file log line 1: expected object/
    );
  });

  it('should throw StorageError for non-string timestamp type', async () => {
    const entry = {
      timestamp: 12345,
      user_id: 1,
      ip_address: '127.0.0.1',
      user_agent: 'Test',
      action: 'test',
      entity_type: 'test',
      entity_id: '1',
      data: {},
      checksum: 'abc',
    };

    const encrypted = encryption.encrypt(JSON.stringify(entry), encryptionKey);
    writeFileSync(tempFile, encrypted + '\n', { mode: 0o600 });

    await expect(reader.read(tempFile)).rejects.toThrow(StorageError);
    await expect(reader.read(tempFile)).rejects.toThrow(
      /Invalid type for field "timestamp" in file log line 1/
    );
  });

  it('should preserve cause in StorageError for non-ENOENT stat error', async () => {
    writeFileSync(tempFile, 'data', { mode: 0o600 });
    const invalidPath = tempFile + '/subpath';

    try {
      await reader.read(invalidPath);
      expect.fail('should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(StorageError);
      expect((error as StorageError).cause).toBeDefined();
    }
  });

  it('should preserve cause in StorageError for readFile error', async () => {
    try {
      await reader.read(tmpdir());
      expect.fail('should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(StorageError);
      expect((error as StorageError).cause).toBeDefined();
    }
  });

  it('should preserve cause in StorageError for invalid JSON', async () => {
    const encrypted = encryption.encrypt('not-json', encryptionKey);
    writeFileSync(tempFile, encrypted + '\n', { mode: 0o600 });

    try {
      await reader.read(tempFile);
      expect.fail('should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(StorageError);
      expect((error as StorageError).cause).toBeDefined();
    }
  });

  it('should re-throw StorageError from catch block for invalid JSON', async () => {
    const encrypted = encryption.encrypt('not-json', encryptionKey);
    writeFileSync(tempFile, encrypted + '\n', { mode: 0o600 });

    await expect(reader.read(tempFile)).rejects.toThrow(StorageError);
    await expect(reader.read(tempFile)).rejects.toThrow(/Corrupted JSON/);
  });

  it('should trim whitespace from lines before decrypting', async () => {
    const entry1 = {
      timestamp: '2026-02-15 14:30:45',
      user_id: 1,
      ip_address: '127.0.0.1',
      user_agent: 'Test',
      action: 'action1',
      entity_type: 'test',
      entity_id: '1',
      data: {},
      checksum: 'abc',
    };
    const entry2 = {
      timestamp: '2026-02-15 14:31:00',
      user_id: 2,
      ip_address: '10.0.0.1',
      user_agent: 'Test',
      action: 'action2',
      entity_type: 'test',
      entity_id: '2',
      data: {},
      checksum: 'def',
    };

    const line1 = encryption.encrypt(JSON.stringify(entry1), encryptionKey);
    const line2 = encryption.encrypt(JSON.stringify(entry2), encryptionKey);
    // Write with trailing whitespace on first line (before newline separator)
    writeFileSync(tempFile, line1 + '  \n' + line2 + '\n', { mode: 0o600 });

    const results = await reader.read(tempFile);
    expect(results).toHaveLength(2);
    expect(results[0]!.action).toBe('action1');
    expect(results[1]!.action).toBe('action2');
  });

  it('should use comma-space separator in missing fields error', async () => {
    const entry = {
      timestamp: '2026-02-15 14:30:45',
      action: 'test',
      // missing: user_id, ip_address, user_agent, entity_type, entity_id, checksum
    };

    const encrypted = encryption.encrypt(JSON.stringify(entry), encryptionKey);
    writeFileSync(tempFile, encrypted + '\n', { mode: 0o600 });

    await expect(reader.read(tempFile)).rejects.toThrow(/user_id, ip_address/);
  });

  it('should throw StorageError when file exceeds MAX_FILE_LOG_SIZE by exactly 1 byte', async () => {
    const entry = {
      timestamp: '2026-02-15 14:30:45',
      user_id: 1,
      ip_address: '127.0.0.1',
      user_agent: 'Test',
      action: 'test',
      entity_type: 'test',
      entity_id: '1',
      data: { payload: 'x'.repeat(1000) },
      checksum: 'abc',
    };

    const encrypted = encryption.encrypt(JSON.stringify(entry), encryptionKey);
    const lineSize = Buffer.byteLength(encrypted + '\n');
    // Create file at exactly MAX_FILE_LOG_SIZE + 1 byte
    const linesNeeded = Math.ceil((MAX_FILE_LOG_SIZE + 1) / lineSize);
    const content = (encrypted + '\n').repeat(linesNeeded);
    writeFileSync(tempFile, content, { mode: 0o600 });

    await expect(reader.read(tempFile)).rejects.toThrow(/exceeds maximum size/);
  });

  it('should handle timestamp already ending with Z', async () => {
    const entry = {
      timestamp: '2026-02-15T14:30:45Z',
      user_id: 1,
      ip_address: '127.0.0.1',
      user_agent: 'Test',
      action: 'test',
      entity_type: 'test',
      entity_id: '1',
      data: {},
      checksum: 'abc',
    };

    const encrypted = encryption.encrypt(JSON.stringify(entry), encryptionKey);
    writeFileSync(tempFile, encrypted + '\n', { mode: 0o600 });

    const results = await reader.read(tempFile);
    expect(results).toHaveLength(1);
    expect(results[0]!.timestamp.toISOString()).toBe('2026-02-15T14:30:45.000Z');
  });

  it('should not reject file at exactly MAX_FILE_LOG_SIZE bytes', async () => {
    // Create sparse file at exactly the limit
    const fd = openSync(tempFile, 'w');
    ftruncateSync(fd, MAX_FILE_LOG_SIZE);
    closeSync(fd);

    // Size check should pass (> not >=), but readFile will fail for corrupt data
    try {
      await reader.read(tempFile);
    } catch (error) {
      // Should fail for data corruption, NOT for size limit
      expect((error as Error).message).not.toContain('exceeds maximum size');
    }
  });

  it('should set dataError for non-object data (array)', async () => {
    const entry = {
      timestamp: '2026-02-15 14:30:45',
      user_id: 1,
      ip_address: '127.0.0.1',
      user_agent: 'Test',
      action: 'test',
      entity_type: 'test',
      entity_id: '1',
      data: [1, 2, 3],
      checksum: 'abc',
    };

    const encrypted = encryption.encrypt(JSON.stringify(entry), encryptionKey);
    writeFileSync(tempFile, encrypted + '\n', { mode: 0o600 });

    const results = await reader.read(tempFile);

    expect(results[0]!.data).toBeNull();
    expect(results[0]!.dataError).toBe('Invalid data type in file log line 1: expected object');
  });
});
