import { coverageConfigDefaults, defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['tests/**/*.{test,spec}.ts'],
    exclude: ['**/node_modules/**', 'dist'],

    coverage: {
      provider: 'v8',
      reporter: ['text', 'html', 'lcov'],
      reportsDirectory: './coverage',
      include: ['src/**/*.ts'],
      exclude: [
        ...coverageConfigDefaults.exclude,
        'src/**/index.ts',
        'src/**/*Interface.ts',
        'src/**/AuditLogResult.ts',
        'src/**/QueryExecutor.ts',
        '**/*.test.ts',
      ],
      thresholds: {
        lines: 100,
        functions: 100,
        branches: 100,
        statements: 100,
      },
    },

    reporters: ['verbose'],

    globals: true,
    mockReset: true,
    restoreMocks: true,
    clearMocks: true,

    testTimeout: 5000,
    hookTimeout: 5000,
  },
});
