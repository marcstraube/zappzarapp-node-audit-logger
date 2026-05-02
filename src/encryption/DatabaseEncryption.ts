import type { EncryptionInterface } from './EncryptionInterface.js';

/**
 * Marker class for database-level encryption
 *
 * This implementation acts as an identity function, returning input unchanged.
 * The actual encryption/decryption is performed by the database using SQL functions
 * like encrypt_text() and decrypt_text(). The AuditLogger detects this class via
 * instanceof and adjusts SQL queries accordingly.
 */
export class DatabaseEncryption implements EncryptionInterface {
  encrypt(plaintext: string, _key: string): string {
    return plaintext;
  }

  decrypt(ciphertext: string, _key: string): string {
    return ciphertext;
  }
}
