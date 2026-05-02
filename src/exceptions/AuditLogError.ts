/**
 * Base error class for audit logging errors
 */
export class AuditLogError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'AuditLogError';
  }
}
