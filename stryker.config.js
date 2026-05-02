/** @type {import('@stryker-mutator/api/core').PartialStrykerOptions} */
export default {
  mutate: ['src/**/*.ts', '!src/**/index.ts'],
  plugins: ['@stryker-mutator/vitest-runner'],
  testRunner: 'vitest',
  checkers: [],
  reporters: ['html', 'clear-text', 'progress'],
  htmlReporter: { fileName: 'reports/mutation/mutation.html' },
  disableTypeChecks: 'src/**/*.ts',
  ignoreStatic: true,
  thresholds: { high: 100, low: 80, break: 100 },
  tempDirName: '.stryker-tmp',
};
