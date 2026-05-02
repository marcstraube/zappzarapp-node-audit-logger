/**
 * Immutable type representing an audit log entry read from storage
 */
export interface AuditLogResult {
  /** Database row ID */
  readonly id: number;
  /** When the action was performed */
  readonly timestamp: Date;
  /** User who performed the action */
  readonly userId: number | null;
  /** Client IP address */
  readonly ipAddress: string;
  /** Action performed */
  readonly action: string;
  /** Entity type */
  readonly entityType: string;
  /** Entity ID */
  readonly entityId: string;
  /** Decrypted context data (null if decryption failed) */
  readonly data: Readonly<Record<string, unknown>> | null;
  /** Client user agent */
  readonly userAgent: string;
  /** Error message when data decoding failed */
  readonly dataError: string | null;
  /** HMAC-SHA-256 tamper-proof checksum */
  readonly checksum: string;
}
