// Main classes
export { AuditLogger } from './AuditLogger.js';
export { NullAuditLogger } from './NullAuditLogger.js';
export { ChecksumCalculator } from './ChecksumCalculator.js';
export { ResultMapper } from './ResultMapper.js';
export { FileLogReader } from './FileLogReader.js';
export { FileLogWriter } from './FileLogWriter.js';

// Interfaces and types
export type { AuditLoggerInterface } from './AuditLoggerInterface.js';
export type { AuditLoggerOptions } from './AuditLogger.js';
export type { ResultMapperContext } from './ResultMapper.js';
export { AuditLogEntry } from './AuditLogEntry.js';
export type { AuditLogResult } from './AuditLogResult.js';
export type { QueryExecutor, DatabaseDialect } from './QueryExecutor.js';

// Encryption
export { AppEncryption } from './encryption/AppEncryption.js';
export { DatabaseEncryption } from './encryption/DatabaseEncryption.js';
export type { EncryptionInterface } from './encryption/EncryptionInterface.js';

// Constants
export { MAX_FILE_LOG_SIZE } from './validation.js';

// Errors
export { AuditLogError } from './exceptions/AuditLogError.js';
export { EncryptionError } from './exceptions/EncryptionError.js';
export { StorageError } from './exceptions/StorageError.js';
