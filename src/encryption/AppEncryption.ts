import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'node:crypto';
import { EncryptionError } from '../exceptions/EncryptionError.js';
import type { EncryptionInterface } from './EncryptionInterface.js';

import { HKDF_SALT } from '../validation.js';

const CIPHER = 'aes-256-gcm' as const;
const IV_LENGTH = 12;
const TAG_LENGTH = 16;
const KEY_LENGTH = 32;

const HKDF_INFO = 'audit-logger-encryption';

/**
 * Application-level encryption using AES-256-GCM via node:crypto
 *
 * Format: base64(iv + authTag + ciphertext)
 * - IV: 12 bytes (random per encryption)
 * - Auth tag: 16 bytes
 * - Ciphertext: variable length
 */
export class AppEncryption implements EncryptionInterface {
  encrypt(plaintext: string, key: string): string {
    try {
      const iv = randomBytes(IV_LENGTH);
      const keyBuffer = this.deriveKey(key);
      const cipher = createCipheriv(CIPHER, keyBuffer, iv);

      // Stryker disable next-line StringLiteral: equivalent — Node.js defaults to utf8 for strings
      const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
      const tag = cipher.getAuthTag();

      return Buffer.concat([iv, tag, encrypted]).toString('base64');
    } catch (error) {
      throw new EncryptionError('Failed to encrypt data', { cause: error });
    }
  }

  decrypt(ciphertext: string, key: string): string {
    if (ciphertext === '' || !/^[A-Za-z0-9+/]*={0,2}$/.test(ciphertext)) {
      throw new EncryptionError('Failed to decode base64 ciphertext');
    }

    const decoded = Buffer.from(ciphertext, 'base64');
    const minLength = IV_LENGTH + TAG_LENGTH;

    if (decoded.length < minLength) {
      throw new EncryptionError('Ciphertext is too short to contain IV and tag');
    }

    try {
      const iv = decoded.subarray(0, IV_LENGTH);
      const tag = decoded.subarray(IV_LENGTH, IV_LENGTH + TAG_LENGTH);
      const encryptedData = decoded.subarray(IV_LENGTH + TAG_LENGTH);
      const keyBuffer = this.deriveKey(key);

      const decipher = createDecipheriv(CIPHER, keyBuffer, iv);
      decipher.setAuthTag(tag);

      const decrypted = Buffer.concat([decipher.update(encryptedData), decipher.final()]);
      return decrypted.toString('utf8');
    } catch (error) {
      throw new EncryptionError(`Failed to decrypt data`, { cause: error });
    }
  }

  /**
   * Derive a 32-byte key using HKDF-SHA-256
   */
  private deriveKey(key: string): Buffer {
    return Buffer.from(hkdfSync('sha256', key, HKDF_SALT, HKDF_INFO, KEY_LENGTH));
  }
}
