export const MAX_FILE_LOG_SIZE = 10_485_760; // 10 MB
export const HKDF_SALT = 'zappzarapp-audit-logger' as const;

const COMMON_REQUIRED_FIELDS = [
  'timestamp',
  'user_id',
  'ip_address',
  'action',
  'entity_type',
  'entity_id',
  'checksum',
] as const;

export const REQUIRED_DB_ROW_FIELDS = [
  'id',
  ...COMMON_REQUIRED_FIELDS,
] as const satisfies readonly string[];
export const REQUIRED_FILE_LOG_FIELDS = [
  ...COMMON_REQUIRED_FIELDS,
  'user_agent',
] as const satisfies readonly string[];

export const DEFAULT_USER_AGENT = 'unknown' as const;

export function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value) as unknown;
  return proto === Object.prototype || proto === null;
}

export function toErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
