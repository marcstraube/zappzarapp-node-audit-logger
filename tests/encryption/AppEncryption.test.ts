import { describe, it, expect, beforeEach } from 'vitest';
import { AppEncryption } from '../../src/encryption/AppEncryption.js';
import { EncryptionError } from '../../src/exceptions/EncryptionError.js';

describe('AppEncryption', () => {
  let encryption: AppEncryption;

  beforeEach(() => {
    encryption = new AppEncryption();
  });

  it('should encrypt and decrypt roundtrip', () => {
    const plaintext = 'Sensitive audit log data';
    const key = 'test-encryption-key-32-characters!';

    const ciphertext = encryption.encrypt(plaintext, key);
    const decrypted = encryption.decrypt(ciphertext, key);

    expect(decrypted).toBe(plaintext);
  });

  it('should encrypt and decrypt empty string', () => {
    const plaintext = '';
    const key = 'test-encryption-key-32-characters!';

    const ciphertext = encryption.encrypt(plaintext, key);
    const decrypted = encryption.decrypt(ciphertext, key);

    expect(decrypted).toBe(plaintext);
  });

  it('should encrypt and decrypt special characters', () => {
    const plaintext = 'Special: \n\r\t Unicode: \u{1F512} JSON: {"key":"value"}';
    const key = 'test-encryption-key-32-characters!';

    const ciphertext = encryption.encrypt(plaintext, key);
    const decrypted = encryption.decrypt(ciphertext, key);

    expect(decrypted).toBe(plaintext);
  });

  it('should work with different key lengths', () => {
    const plaintext = 'Test data';

    // Short key (HKDF handles any length)
    const shortKey = 'short';
    const ciphertext1 = encryption.encrypt(plaintext, shortKey);
    expect(encryption.decrypt(ciphertext1, shortKey)).toBe(plaintext);

    // Longer key
    const longKey = 'a-much-longer-encryption-key-for-testing-purposes-here';
    const ciphertext2 = encryption.encrypt(plaintext, longKey);
    expect(encryption.decrypt(ciphertext2, longKey)).toBe(plaintext);
  });

  it('should throw EncryptionError when decrypting with wrong key', () => {
    const plaintext = 'Secret data';
    const correctKey = 'correct-key';
    const wrongKey = 'wrong-key';

    const ciphertext = encryption.encrypt(plaintext, correctKey);

    expect(() => encryption.decrypt(ciphertext, wrongKey)).toThrow(EncryptionError);
    expect(() => encryption.decrypt(ciphertext, wrongKey)).toThrow('Failed to decrypt data');
  });

  it('should throw EncryptionError for truncated ciphertext', () => {
    const plaintext = 'Test';
    const key = 'test-encryption-key-32-characters!';

    const ciphertext = encryption.encrypt(plaintext, key);
    const decoded = Buffer.from(ciphertext, 'base64');

    // Truncate to less than IV (12) + Tag (16) = 28 bytes
    const truncated = decoded.subarray(0, 20).toString('base64');

    expect(() => encryption.decrypt(truncated, key)).toThrow(EncryptionError);
    expect(() => encryption.decrypt(truncated, key)).toThrow(
      'Ciphertext is too short to contain IV and tag'
    );
  });

  it('should throw EncryptionError for empty ciphertext', () => {
    const key = 'test-encryption-key-32-characters!';

    expect(() => encryption.decrypt('', key)).toThrow(EncryptionError);
    expect(() => encryption.decrypt('', key)).toThrow('Failed to decode base64 ciphertext');
  });

  it('should produce different output each time due to random IV', () => {
    const plaintext = 'Same plaintext';
    const key = 'test-encryption-key-32-characters!';

    const ciphertext1 = encryption.encrypt(plaintext, key);
    const ciphertext2 = encryption.encrypt(plaintext, key);

    // Different ciphertexts due to random IV
    expect(ciphertext1).not.toBe(ciphertext2);

    // But both decrypt to same plaintext
    expect(encryption.decrypt(ciphertext1, key)).toBe(plaintext);
    expect(encryption.decrypt(ciphertext2, key)).toBe(plaintext);
  });

  it('should return base64 encoded string', () => {
    const plaintext = 'Test data';
    const key = 'test-encryption-key-32-characters!';

    const ciphertext = encryption.encrypt(plaintext, key);

    // Should be valid base64
    expect(ciphertext).toMatch(/^[A-Za-z0-9+/]+=*$/);
    expect(() => Buffer.from(ciphertext, 'base64')).not.toThrow();
  });

  it('should throw EncryptionError for manipulated ciphertext', () => {
    const plaintext = 'Original data';
    const key = 'test-encryption-key-32-characters!';

    const ciphertext = encryption.encrypt(plaintext, key);
    const decoded = Buffer.from(ciphertext, 'base64');

    // Flip a bit in the ciphertext portion (after IV and tag)
    const manipulated = Buffer.from(decoded);
    manipulated[30] = manipulated[30]! ^ 1;
    const manipulatedBase64 = manipulated.toString('base64');

    expect(() => encryption.decrypt(manipulatedBase64, key)).toThrow(EncryptionError);
    expect(() => encryption.decrypt(manipulatedBase64, key)).toThrow('Failed to decrypt data');
  });

  it('should handle large data', () => {
    const plaintext = 'x'.repeat(10000);
    const key = 'test-encryption-key-32-characters!';

    const ciphertext = encryption.encrypt(plaintext, key);
    const decrypted = encryption.decrypt(ciphertext, key);

    expect(decrypted).toBe(plaintext);
  });

  it('should throw EncryptionError for invalid base64 input', () => {
    const key = 'test-encryption-key-32-characters!';

    expect(() => encryption.decrypt('not!valid@base64#', key)).toThrow(EncryptionError);
    expect(() => encryption.decrypt('not!valid@base64#', key)).toThrow(
      'Failed to decode base64 ciphertext'
    );
  });

  it('should isolate keys via HKDF - different keys produce different ciphertext', () => {
    const plaintext = 'Same data';
    const key1 = 'first-key-for-testing-purposes!!';
    const key2 = 'second-key-for-testing-purposes!';

    const cipher1 = encryption.encrypt(plaintext, key1);
    const cipher2 = encryption.encrypt(plaintext, key2);

    // Different keys produce different ciphertext (even ignoring random IV,
    // decryption with wrong key must fail)
    expect(() => encryption.decrypt(cipher1, key2)).toThrow(EncryptionError);
    expect(() => encryption.decrypt(cipher2, key1)).toThrow(EncryptionError);

    // But correct key works
    expect(encryption.decrypt(cipher1, key1)).toBe(plaintext);
    expect(encryption.decrypt(cipher2, key2)).toBe(plaintext);
  });

  it('should detect auth tag tampering (bit flip in tag portion)', () => {
    const plaintext = 'Tamper test';
    const key = 'test-encryption-key-32-characters!';

    const ciphertext = encryption.encrypt(plaintext, key);
    const decoded = Buffer.from(ciphertext, 'base64');

    // Flip a bit in the auth tag (bytes 12-27)
    const tampered = Buffer.from(decoded);
    tampered[15] = tampered[15]! ^ 0xff;
    const tamperedBase64 = tampered.toString('base64');

    expect(() => encryption.decrypt(tamperedBase64, key)).toThrow(EncryptionError);
  });

  it('should throw EncryptionError when internal crypto operation fails', () => {
    const broken = new AppEncryption();
    // Override private deriveKey to simulate crypto failure
    (broken as unknown as { deriveKey: () => never }).deriveKey = () => {
      throw new Error('crypto failure');
    };

    expect(() => broken.encrypt('test', 'any-key')).toThrow(EncryptionError);
    expect(() => broken.encrypt('test', 'any-key')).toThrow('Failed to encrypt data');
  });

  it('should preserve cause in EncryptionError on encrypt failure', () => {
    const broken = new AppEncryption();
    (broken as unknown as { deriveKey: () => never }).deriveKey = () => {
      throw new Error('crypto failure');
    };

    try {
      broken.encrypt('test', 'any-key');
      expect.fail('should have thrown');
    } catch (error) {
      expect((error as EncryptionError).cause).toBeInstanceOf(Error);
      expect(((error as EncryptionError).cause as Error).message).toBe('crypto failure');
    }
  });

  it('should preserve cause in EncryptionError on decrypt failure', () => {
    const key = 'test-encryption-key-32-characters!';
    const ciphertext = encryption.encrypt('test', key);

    try {
      encryption.decrypt(ciphertext, 'wrong-key-for-decrypt-32-chars!!');
      expect.fail('should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(EncryptionError);
      expect((error as EncryptionError).cause).toBeDefined();
    }
  });
});
