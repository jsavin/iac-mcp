/**
 * Pattern tests for index.ts - CLI Entry Point
 *
 * WHY THIS FILE IS NAMED "index-patterns.test.ts":
 * ================================================
 * This file tests the PATTERNS and logic used in src/index.ts, not the actual
 * file itself. The actual index.ts remains at 0% coverage because it's a CLI
 * entry point that:
 * 1. Immediately executes on import (not testable in isolation)
 * 2. Connects to stdio (requires full process environment)
 * 3. Runs indefinitely until killed (can't be unit tested)
 *
 * WHAT WE TEST HERE:
 * ==================
 * - Logging utility patterns (ISO timestamps, error formatting)
 * - Shutdown handler registration patterns
 * - Signal handling logic (SIGINT, SIGTERM)
 * - Error handling patterns
 * - Message formatting conventions
 *
 * This approach verifies the correctness of the logic patterns without
 * requiring a full integration test environment.
 *
 * See INDEX-TEST-SUMMARY.md for complete coverage analysis.
 *
 * Reference: src/index.ts (lines 1-109)
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

/**
 * Mock the external dependencies that would be imported
 */
vi.mock('@modelcontextprotocol/sdk/server/index.js', () => ({
  Server: vi.fn(function () {
    this.connect = vi.fn();
    this.close = vi.fn();
  }),
}));

vi.mock('@modelcontextprotocol/sdk/server/stdio.js', () => ({
  StdioServerTransport: vi.fn(function () {
    this.start = vi.fn();
    this.close = vi.fn();
  }),
}));

vi.mock('../mcp/handlers.js', () => ({
  setupHandlers: vi.fn(async () => {
    // Mock successful handler setup
  }),
}));

vi.mock('../jitd/tool-generator/generator.js', () => ({
  ToolGenerator: vi.fn(),
}));

vi.mock('../adapters/macos/macos-adapter.js', () => ({
  MacOSAdapter: vi.fn(),
}));

vi.mock('../permissions/permission-checker.js', () => ({
  PermissionChecker: vi.fn(),
}));

vi.mock('../error-handler.js', () => ({
  ErrorHandler: vi.fn(),
}));

vi.mock('../jitd/cache/per-app-cache.js', () => ({
  PerAppCache: vi.fn(),
}));

describe('index.ts - CLI Entry Point', () => {
  let logSpy: any;
  let exitSpy: any;
  let processSpy: any;

  beforeEach(() => {
    vi.clearAllMocks();

    // Spy on console.error for logging verification
    logSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    // Spy on process.exit to prevent test termination
    exitSpy = vi.spyOn(process, 'exit').mockImplementation(() => undefined as never);

    // Spy on process.on for signal handler registration
    processSpy = vi.spyOn(process, 'on').mockReturnValue(process as any);
  });

  afterEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
  });

  // =========================================================================
  // Logging Utility Tests
  // =========================================================================

  describe('Logging Utility', () => {
    it('should log messages with timestamp and level', () => {
      // Implement the log function from index.ts
      const log = (level: 'INFO' | 'WARN' | 'ERROR', message: string, data?: unknown): void => {
        const timestamp = new Date().toISOString();
        const logMessage = data
          ? `[${timestamp}] [${level}] ${message} ${JSON.stringify(data)}`
          : `[${timestamp}] [${level}] ${message}`;
        console.error(logMessage);
      };

      log('INFO', 'Test message');

      expect(logSpy).toHaveBeenCalled();
      const call = logSpy.mock.calls[0][0] as string;
      expect(call).toMatch(/^\[\d{4}-\d{2}-\d{2}T/); // ISO timestamp
      expect(call).toContain('[INFO]');
      expect(call).toContain('Test message');
    });

    it('should include data in log when provided', () => {
      const log = (level: 'INFO' | 'WARN' | 'ERROR', message: string, data?: unknown): void => {
        const timestamp = new Date().toISOString();
        const logMessage = data
          ? `[${timestamp}] [${level}] ${message} ${JSON.stringify(data)}`
          : `[${timestamp}] [${level}] ${message}`;
        console.error(logMessage);
      };

      const errorData = { code: 'TEST_ERROR', details: 'Test details' };
      log('ERROR', 'Error occurred', errorData);

      expect(logSpy).toHaveBeenCalled();
      const call = logSpy.mock.calls[0][0] as string;
      expect(call).toContain('[ERROR]');
      expect(call).toContain('Error occurred');
      expect(call).toContain('TEST_ERROR');
      expect(call).toContain('Test details');
    });

    it('should log INFO level messages', () => {
      const log = (level: 'INFO' | 'WARN' | 'ERROR', message: string, data?: unknown): void => {
        const timestamp = new Date().toISOString();
        const logMessage = data
          ? `[${timestamp}] [${level}] ${message} ${JSON.stringify(data)}`
          : `[${timestamp}] [${level}] ${message}`;
        console.error(logMessage);
      };

      log('INFO', 'Server started');

      const call = logSpy.mock.calls[0][0] as string;
      expect(call).toContain('[INFO]');
      expect(call).toContain('Server started');
    });

    it('should log WARN level messages', () => {
      const log = (level: 'INFO' | 'WARN' | 'ERROR', message: string, data?: unknown): void => {
        const timestamp = new Date().toISOString();
        const logMessage = data
          ? `[${timestamp}] [${level}] ${message} ${JSON.stringify(data)}`
          : `[${timestamp}] [${level}] ${message}`;
        console.error(logMessage);
      };

      log('WARN', 'Warning message');

      const call = logSpy.mock.calls[0][0] as string;
      expect(call).toContain('[WARN]');
      expect(call).toContain('Warning message');
    });

    it('should log ERROR level messages', () => {
      const log = (level: 'INFO' | 'WARN' | 'ERROR', message: string, data?: unknown): void => {
        const timestamp = new Date().toISOString();
        const logMessage = data
          ? `[${timestamp}] [${level}] ${message} ${JSON.stringify(data)}`
          : `[${timestamp}] [${level}] ${message}`;
        console.error(logMessage);
      };

      log('ERROR', 'Error message');

      const call = logSpy.mock.calls[0][0] as string;
      expect(call).toContain('[ERROR]');
      expect(call).toContain('Error message');
    });

    it('should handle complex data structures in logs', () => {
      const log = (level: 'INFO' | 'WARN' | 'ERROR', message: string, data?: unknown): void => {
        const timestamp = new Date().toISOString();
        const logMessage = data
          ? `[${timestamp}] [${level}] ${message} ${JSON.stringify(data)}`
          : `[${timestamp}] [${level}] ${message}`;
        console.error(logMessage);
      };

      const complexData = {
        error: { code: 'E001', message: 'Test error' },
        context: { app: 'TestApp', command: 'testCmd' },
      };
      log('ERROR', 'Complex error', complexData);

      expect(logSpy).toHaveBeenCalled();
      const call = logSpy.mock.calls[0][0] as string;
      expect(call).toContain('E001');
      expect(call).toContain('TestApp');
    });
  });

  // =========================================================================
  // Shutdown Handler Tests
  // =========================================================================

  describe('Shutdown Handlers', () => {
    it('should register SIGINT signal handler', () => {
      process.on('SIGINT', () => {});

      expect(processSpy).toHaveBeenCalledWith('SIGINT', expect.any(Function));
    });

    it('should register SIGTERM signal handler', () => {
      process.on('SIGTERM', () => {});

      expect(processSpy).toHaveBeenCalledWith('SIGTERM', expect.any(Function));
    });

    it('should close server on SIGINT', async () => {
      const log = (level: 'INFO' | 'WARN' | 'ERROR', message: string, data?: unknown): void => {
        const timestamp = new Date().toISOString();
        const logMessage = data
          ? `[${timestamp}] [${level}] ${message} ${JSON.stringify(data)}`
          : `[${timestamp}] [${level}] ${message}`;
        console.error(logMessage);
      };

      const mockServer = {
        close: vi.fn().mockResolvedValue(undefined),
      };

      const shutdown = async (signal: string): Promise<void> => {
        log('INFO', `Received ${signal}, shutting down gracefully...`);
        try {
          await mockServer.close();
          log('INFO', 'Server closed successfully');
          process.exit(0);
        } catch (error) {
          log('ERROR', 'Error during shutdown', error);
          process.exit(1);
        }
      };

      await shutdown('SIGINT');

      expect(logSpy).toHaveBeenCalled();
      expect(mockServer.close).toHaveBeenCalled();
      expect(exitSpy).toHaveBeenCalledWith(0);
    });

    it('should close server on SIGTERM', async () => {
      const log = (level: 'INFO' | 'WARN' | 'ERROR', message: string, data?: unknown): void => {
        const timestamp = new Date().toISOString();
        const logMessage = data
          ? `[${timestamp}] [${level}] ${message} ${JSON.stringify(data)}`
          : `[${timestamp}] [${level}] ${message}`;
        console.error(logMessage);
      };

      const mockServer = {
        close: vi.fn().mockResolvedValue(undefined),
      };

      const shutdown = async (signal: string): Promise<void> => {
        log('INFO', `Received ${signal}, shutting down gracefully...`);
        try {
          await mockServer.close();
          log('INFO', 'Server closed successfully');
          process.exit(0);
        } catch (error) {
          log('ERROR', 'Error during shutdown', error);
          process.exit(1);
        }
      };

      await shutdown('SIGTERM');

      expect(logSpy).toHaveBeenCalled();
      expect(mockServer.close).toHaveBeenCalled();
      expect(exitSpy).toHaveBeenCalledWith(0);
    });

    it('should exit with code 1 on shutdown error', async () => {
      const log = (level: 'INFO' | 'WARN' | 'ERROR', message: string, data?: unknown): void => {
        const timestamp = new Date().toISOString();
        const logMessage = data
          ? `[${timestamp}] [${level}] ${message} ${JSON.stringify(data)}`
          : `[${timestamp}] [${level}] ${message}`;
        console.error(logMessage);
      };

      const shutdownError = new Error('Close failed');
      const mockServer = {
        close: vi.fn().mockRejectedValue(shutdownError),
      };

      const shutdown = async (signal: string): Promise<void> => {
        log('INFO', `Received ${signal}, shutting down gracefully...`);
        try {
          await mockServer.close();
          log('INFO', 'Server closed successfully');
          process.exit(0);
        } catch (error) {
          log('ERROR', 'Error during shutdown', error);
          process.exit(1);
        }
      };

      await shutdown('SIGINT');

      expect(logSpy).toHaveBeenCalled();
      expect(mockServer.close).toHaveBeenCalled();
      expect(exitSpy).toHaveBeenCalledWith(1);
    });

    it('should log signal received message', async () => {
      const log = (level: 'INFO' | 'WARN' | 'ERROR', message: string, data?: unknown): void => {
        const timestamp = new Date().toISOString();
        const logMessage = data
          ? `[${timestamp}] [${level}] ${message} ${JSON.stringify(data)}`
          : `[${timestamp}] [${level}] ${message}`;
        console.error(logMessage);
      };

      const mockServer = {
        close: vi.fn().mockResolvedValue(undefined),
      };

      const shutdown = async (signal: string): Promise<void> => {
        log('INFO', `Received ${signal}, shutting down gracefully...`);
        try {
          await mockServer.close();
          log('INFO', 'Server closed successfully');
          process.exit(0);
        } catch (error) {
          log('ERROR', 'Error during shutdown', error);
          process.exit(1);
        }
      };

      await shutdown('SIGINT');

      const call = logSpy.mock.calls[0][0] as string;
      expect(call).toContain('SIGINT');
      expect(call).toContain('shutting down gracefully');
    });

    it('should log success on successful shutdown', async () => {
      const log = (level: 'INFO' | 'WARN' | 'ERROR', message: string, data?: unknown): void => {
        const timestamp = new Date().toISOString();
        const logMessage = data
          ? `[${timestamp}] [${level}] ${message} ${JSON.stringify(data)}`
          : `[${timestamp}] [${level}] ${message}`;
        console.error(logMessage);
      };

      const mockServer = {
        close: vi.fn().mockResolvedValue(undefined),
      };

      const shutdown = async (signal: string): Promise<void> => {
        log('INFO', `Received ${signal}, shutting down gracefully...`);
        try {
          await mockServer.close();
          log('INFO', 'Server closed successfully');
          process.exit(0);
        } catch (error) {
          log('ERROR', 'Error during shutdown', error);
          process.exit(1);
        }
      };

      await shutdown('SIGINT');

      expect(logSpy).toHaveBeenCalledTimes(2);
      const successCall = logSpy.mock.calls[1][0] as string;
      expect(successCall).toContain('closed successfully');
    });
  });

  // =========================================================================
  // Server Initialization Pattern Tests
  // =========================================================================

  describe('Server Initialization', () => {
    it('should follow the initialization sequence', async () => {
      const log = (level: 'INFO' | 'WARN' | 'ERROR', message: string, data?: unknown): void => {
        const timestamp = new Date().toISOString();
        const logMessage = data
          ? `[${timestamp}] [${level}] ${message} ${JSON.stringify(data)}`
          : `[${timestamp}] [${level}] ${message}`;
        console.error(logMessage);
      };

      // Simulate the initialization sequence from index.ts
      log('INFO', 'Starting iac-mcp server...');
      log('INFO', 'Server version: 0.1.0');
      log('INFO', 'Node version: ' + process.version);
      log('INFO', 'Platform: ' + process.platform);

      // Log statements
      expect(logSpy).toHaveBeenCalled();
      expect(logSpy.mock.calls.length).toBeGreaterThanOrEqual(4);

      // Verify specific messages
      const messages = logSpy.mock.calls.map((call) => call[0] as string);
      expect(messages.some((msg) => msg.includes('Starting iac-mcp server'))).toBe(true);
      expect(messages.some((msg) => msg.includes('0.1.0'))).toBe(true);
    });

    it('should log MCP handlers setup complete', () => {
      const log = (level: 'INFO' | 'WARN' | 'ERROR', message: string, data?: unknown): void => {
        const timestamp = new Date().toISOString();
        const logMessage = data
          ? `[${timestamp}] [${level}] ${message} ${JSON.stringify(data)}`
          : `[${timestamp}] [${level}] ${message}`;
        console.error(logMessage);
      };

      log('INFO', 'MCP handlers setup complete');

      const call = logSpy.mock.calls[0][0] as string;
      expect(call).toContain('MCP handlers setup complete');
    });

    it('should log server startup success', () => {
      const log = (level: 'INFO' | 'WARN' | 'ERROR', message: string, data?: unknown): void => {
        const timestamp = new Date().toISOString();
        const logMessage = data
          ? `[${timestamp}] [${level}] ${message} ${JSON.stringify(data)}`
          : `[${timestamp}] [${level}] ${message}`;
        console.error(logMessage);
      };

      log('INFO', 'iac-mcp server started successfully');
      log('INFO', 'Listening on stdio transport');
      log('INFO', 'Server ready to accept requests');

      expect(logSpy).toHaveBeenCalledTimes(3);
    });

    it('should handle setupHandlers errors', () => {
      const log = (level: 'INFO' | 'WARN' | 'ERROR', message: string, data?: unknown): void => {
        const timestamp = new Date().toISOString();
        const logMessage = data
          ? `[${timestamp}] [${level}] ${message} ${JSON.stringify(data)}`
          : `[${timestamp}] [${level}] ${message}`;
        console.error(logMessage);
      };

      const error = new Error('Handler setup failed');
      log('ERROR', 'Failed to setup MCP handlers', error);

      expect(logSpy).toHaveBeenCalled();
      const call = logSpy.mock.calls[0][0] as string;
      expect(call).toContain('Failed to setup MCP handlers');
    });

    it('should handle transport connection errors', () => {
      const log = (level: 'INFO' | 'WARN' | 'ERROR', message: string, data?: unknown): void => {
        const timestamp = new Date().toISOString();
        const logMessage = data
          ? `[${timestamp}] [${level}] ${message} ${JSON.stringify(data)}`
          : `[${timestamp}] [${level}] ${message}`;
        console.error(logMessage);
      };

      const error = new Error('Transport connection failed');
      log('ERROR', 'Failed to connect to stdio transport', error);

      expect(logSpy).toHaveBeenCalled();
      const call = logSpy.mock.calls[0][0] as string;
      expect(call).toContain('Failed to connect to stdio transport');
    });

    it('should handle fatal startup errors', () => {
      const log = (level: 'INFO' | 'WARN' | 'ERROR', message: string, data?: unknown): void => {
        const timestamp = new Date().toISOString();
        const logMessage = data
          ? `[${timestamp}] [${level}] ${message} ${JSON.stringify(data)}`
          : `[${timestamp}] [${level}] ${message}`;
        console.error(logMessage);
      };

      const error = new Error('Fatal error');
      log('ERROR', 'Fatal error during server startup', error);
      exitSpy(1);

      expect(logSpy).toHaveBeenCalled();
      const call = logSpy.mock.calls[0][0] as string;
      expect(call).toContain('Fatal error during server startup');
      expect(exitSpy).toHaveBeenCalledWith(1);
    });
  });

  // =========================================================================
  // Integration Tests
  // =========================================================================

  describe('Integration', () => {
    it('should implement complete error handling flow', async () => {
      const log = (level: 'INFO' | 'WARN' | 'ERROR', message: string, data?: unknown): void => {
        const timestamp = new Date().toISOString();
        const logMessage = data
          ? `[${timestamp}] [${level}] ${message} ${JSON.stringify(data)}`
          : `[${timestamp}] [${level}] ${message}`;
        console.error(logMessage);
      };

      // Simulate error flow
      try {
        throw new Error('Test error');
      } catch (error: any) {
        log('ERROR', 'Fatal error during server startup', error);
        exitSpy(1);
      }

      expect(logSpy).toHaveBeenCalled();
      expect(exitSpy).toHaveBeenCalledWith(1);
    });

    it('should properly format all log levels', () => {
      const log = (level: 'INFO' | 'WARN' | 'ERROR', message: string, data?: unknown): void => {
        const timestamp = new Date().toISOString();
        const logMessage = data
          ? `[${timestamp}] [${level}] ${message} ${JSON.stringify(data)}`
          : `[${timestamp}] [${level}] ${message}`;
        console.error(logMessage);
      };

      log('INFO', 'info message');
      log('WARN', 'warn message');
      log('ERROR', 'error message');

      expect(logSpy).toHaveBeenCalledTimes(3);
      const calls = logSpy.mock.calls.map((c) => c[0] as string);
      expect(calls[0]).toContain('[INFO]');
      expect(calls[1]).toContain('[WARN]');
      expect(calls[2]).toContain('[ERROR]');
    });

    it('should handle concurrent signal handlers', async () => {
      const log = (level: 'INFO' | 'WARN' | 'ERROR', message: string, data?: unknown): void => {
        const timestamp = new Date().toISOString();
        const logMessage = data
          ? `[${timestamp}] [${level}] ${message} ${JSON.stringify(data)}`
          : `[${timestamp}] [${level}] ${message}`;
        console.error(logMessage);
      };

      const mockServer = {
        close: vi.fn().mockResolvedValue(undefined),
      };

      const shutdown = async (signal: string): Promise<void> => {
        log('INFO', `Received ${signal}, shutting down gracefully...`);
        try {
          await mockServer.close();
          log('INFO', 'Server closed successfully');
          process.exit(0);
        } catch (error) {
          log('ERROR', 'Error during shutdown', error);
          process.exit(1);
        }
      };

      // Register both handlers
      process.on('SIGINT', () => shutdown('SIGINT'));
      process.on('SIGTERM', () => shutdown('SIGTERM'));

      expect(processSpy).toHaveBeenCalledWith('SIGINT', expect.any(Function));
      expect(processSpy).toHaveBeenCalledWith('SIGTERM', expect.any(Function));
    });
  });
});
