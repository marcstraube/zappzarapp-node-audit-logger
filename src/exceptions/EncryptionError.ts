import { AuditLogError } from './AuditLogError.js';

/**
 * Error thrown when encryption or decryption fails
 */
export class EncryptionError extends AuditLogError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'EncryptionError';
  }
}
