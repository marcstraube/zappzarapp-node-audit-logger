/**
 * Minimal database abstraction for audit logging
 *
 * The package defines its own DB interface to avoid depending on any
 * specific database driver (pg, mysql2, etc.). Consumers wrap their
 * existing database connection to satisfy this interface.
 */
export interface QueryExecutor {
  /**
   * Execute a query that returns rows
   */
  query<T extends Record<string, unknown> = Record<string, unknown>>(
    sql: string,
    params?: unknown[]
  ): Promise<T[]>;

  /**
   * Execute a statement that modifies data
   */
  execute(sql: string, params?: unknown[]): Promise<{ affectedRows: number }>;
}

/**
 * Database dialect for SQL generation
 *
 * - postgres: Uses $1, $2, ... placeholders, RETURNING id
 * - mysql: Uses ?, ?, ... placeholders, LAST_INSERT_ID()
 */
export type DatabaseDialect = 'postgres' | 'mysql';
