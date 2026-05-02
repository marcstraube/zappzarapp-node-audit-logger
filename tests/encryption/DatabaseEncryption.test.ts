import { describe, it, expect, beforeEach } from 'vitest';
import { DatabaseEncryption } from '../../src/encryption/DatabaseEncryption.js';

describe('DatabaseEncryption', () => {
  let encryption: DatabaseEncryption;

  beforeEach(() => {
    encryption = new DatabaseEncryption();
  });

  it('should return plaintext unchanged on encrypt', () => {
    const plaintext = 'Sensitive data';
    const key = 'any-key';

    const result = encryption.encrypt(plaintext, key);

    expect(result).toBe(plaintext);
  });

  it('should return empty string unchanged on encrypt', () => {
    const result = encryption.encrypt('', 'any-key');

    expect(result).toBe('');
  });

  it('should handle special characters in encrypt', () => {
    const plaintext = 'Special: \n\r\t Unicode: \u{1F512}';
    const result = encryption.encrypt(plaintext, 'any-key');

    expect(result).toBe(plaintext);
  });

  it('should return ciphertext unchanged on decrypt', () => {
    const ciphertext = 'Any ciphertext value';
    const key = 'any-key';

    const result = encryption.decrypt(ciphertext, key);

    expect(result).toBe(ciphertext);
  });

  it('should return empty string unchanged on decrypt', () => {
    const result = encryption.decrypt('', 'any-key');

    expect(result).toBe('');
  });

  it('should be an identity function for encrypt/decrypt', () => {
    const data = 'Test data for database encryption';
    const key = 'database-key';

    const encrypted = encryption.encrypt(data, key);
    expect(encrypted).toBe(data);

    const decrypted = encryption.decrypt(encrypted, key);
    expect(decrypted).toBe(data);
  });

  it('should ignore the key parameter', () => {
    const plaintext = 'Test data';

    const result1 = encryption.encrypt(plaintext, 'first-key');
    const result2 = encryption.encrypt(plaintext, 'second-key');

    expect(result1).toBe(plaintext);
    expect(result2).toBe(plaintext);
  });
});
