/**
 * Encryption strategy interface for audit log data
 */
export interface EncryptionInterface {
  /**
   * Encrypt plaintext data
   *
   * @throws EncryptionError
   */
  encrypt(plaintext: string, key: string): string;

  /**
   * Decrypt ciphertext data
   *
   * @throws EncryptionError
   */
  decrypt(ciphertext: string, key: string): string;
}
