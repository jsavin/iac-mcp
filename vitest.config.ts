import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    testTimeout: 10000, // Increase timeout for tests that validate long timeouts
    // Limit resource usage to prevent memory exhaustion
    pool: 'threads',
    poolOptions: {
      threads: {
        maxThreads: 4,  // Limit parallel test threads
        minThreads: 1,
      },
    },
    // Isolate tests to prevent memory accumulation
    isolate: true,
    // Limit concurrent file processing
    maxConcurrency: 5,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      exclude: [
        'node_modules/',
        'dist/',
        'tests/',
        '**/*.test.ts',
        '**/*.config.ts',
      ],
      all: true,
      reportOnFailure: true,
    },
  },
});
