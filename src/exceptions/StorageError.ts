import { AuditLogError } from './AuditLogError.js';

/**
 * Error thrown when database or file storage operations fail
 */
export class StorageError extends AuditLogError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'StorageError';
  }
}
