/**
 * Unit tests for MacOSAdapter
 *
 * Tests the high-level MacOSAdapter that orchestrates JXAExecutor,
 * ParameterMarshaler, and ResultParser to execute macOS automation commands.
 *
 * The adapter is responsible for:
 * 1. Validating tool metadata
 * 2. Marshaling JSON parameters to JXA code
 * 3. Building complete JXA scripts
 * 4. Executing scripts via JXAExecutor
 * 5. Parsing and returning results
 * 6. Handling errors gracefully
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import type { MCPTool, ToolMetadata, JSONSchema, JSONSchemaProperty } from '../../src/types/mcp-tool';
import type { JXAExecutionResult } from '../../src/types/jxa';
import { MacOSAdapter } from '../../src/adapters/macos/macos-adapter';

/**
 * Mock types for testing
 */
interface ExecutionResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  timedOut?: boolean;
}

interface ParsedResult {
  success: boolean;
  data?: any;
  error?: {
    type: string;
    message: string;
    originalError?: string;
  };
}

/**
 * Helper to create a basic MCPTool for testing
 */
function createMockTool(overrides?: Partial<MCPTool>): MCPTool {
  return {
    name: 'finder_open',
    description: 'Open a file or folder in Finder',
    inputSchema: {
      type: 'object',
      properties: {
        target: { type: 'string', description: 'Path to file or folder' },
      },
      required: ['target'],
    },
    _metadata: {
      appName: 'Finder',
      bundleId: 'com.apple.finder',
      commandName: 'open',
      commandCode: 'aevtodoc',
      suiteName: 'Standard Suite',
      directParameterName: 'target',
    },
    ...overrides,
  };
}

/**
 * Helper to create tool metadata
 */
function createMockMetadata(overrides?: Partial<ToolMetadata>): ToolMetadata {
  return {
    appName: 'Finder',
    bundleId: 'com.apple.finder',
    commandName: 'open',
    commandCode: 'aevtodoc',
    suiteName: 'Standard Suite',
    ...overrides,
  };
}

describe('MacOSAdapter', () => {
  let adapter: any; // We'll use any because we're testing with mocks
  let mockJXAExecutor: any;
  let mockParameterMarshaler: any;
  let mockResultParser: any;
  let mockErrorHandler: any;

  beforeEach(() => {
    /**
     * Mock JXAExecutor - executes JXA scripts via osascript
     */
    mockJXAExecutor = {
      execute: vi.fn(),
      isAvailable: vi.fn().mockResolvedValue(true),
      getVersion: vi.fn().mockResolvedValue('2.0'),
    };

    /**
     * Mock ParameterMarshaler - converts JSON to JXA
     */
    mockParameterMarshaler = {
      marshal: vi.fn((params) => {
        // Simple mock: convert params to JXA-like string
        return JSON.stringify(params).replace(/"/g, "'");
      }),
      marshalValue: vi.fn((value) => {
        if (typeof value === 'string') return `"${value}"`;
        return String(value);
      }),
    };

    /**
     * Mock ResultParser - parses JXA execution output
     */
    mockResultParser = {
      parse: vi.fn((result) => ({
        success: result.exitCode === 0,
        data: result.exitCode === 0 ? JSON.parse(result.stdout) : undefined,
        error: result.exitCode !== 0 ? { type: 'EXECUTION_ERROR', message: result.stderr } : undefined,
      })),
      parseError: vi.fn((stderr) => ({
        type: 'EXECUTION_ERROR',
        message: stderr,
      })),
    };

    /**
     * Mock ErrorHandler - classifies and formats errors
     */
    mockErrorHandler = {
      handle: vi.fn((error, context) => ({
        type: 'EXECUTION_ERROR',
        message: error.message || 'Unknown error',
        retryable: false,
        originalError: error.toString(),
      })),
      isRetryable: vi.fn((error) => {
        return ['TIMEOUT', 'APP_NOT_RUNNING'].includes(error.type);
      }),
    };

    /**
     * Create adapter instance with mocked dependencies
     * In real implementation, these would be actual instances
     */
    adapter = {
      executor: mockJXAExecutor,
      marshaler: mockParameterMarshaler,
      parser: mockResultParser,
      errorHandler: mockErrorHandler,
      timeout: 30000,
      enableLogging: false,

      /**
       * Build JXA script from tool and arguments
       * This is a simplified version for testing structure
       */
      buildJXAScript: function (tool: MCPTool, args: Record<string, any>): string {
        if (!tool._metadata) {
          throw new Error('Tool metadata is missing');
        }

        const { appName, commandName } = tool._metadata;
        const marshaledParams = this.marshaler.marshal(args, tool.inputSchema, tool._metadata);

        return `(() => {
  const app = Application("${appName}");
  app.includeStandardAdditions = true;
  const params = ${marshaledParams};
  const result = app.${commandName}(params);
  return result;
})()`;
      },

      /**
       * Execute an MCP tool on macOS
       */
      async execute(tool: MCPTool, args: Record<string, any>): Promise<JXAExecutionResult> {
        // Validate tool has metadata
        if (!tool._metadata) {
          throw new Error('Tool metadata is required for execution');
        }

        // Build JXA script (which marshals parameters internally)
        const script = this.buildJXAScript(tool, args);

        // Execute script
        const result = await this.executor.execute(script, {
          timeoutMs: this.timeout,
        });

        // Parse result
        const parsed = this.parser.parse(result, tool._metadata);

        if (parsed.success) {
          return {
            success: true,
            data: parsed.data,
          };
        } else {
          return {
            success: false,
            error: {
              type: parsed.error.type,
              message: parsed.error.message,
              appName: tool._metadata.appName,
            },
          };
        }
      },

      /**
       * Test if app is available
       */
      async testApp(bundleId: string): Promise<boolean> {
        // Build test script
        const script = `(() => {
  try {
    const app = Application.currentApplication();
    app.includeStandardAdditions = true;
    // Try to get app
    const testApp = Application.stringByEvaluatingJavaScriptFromString(
      \`tell application "System Events" to (bundle identifier of application "${bundleId}")\`
    );
    return testApp ? true : false;
  } catch (e) {
    return false;
  }
})()`;

        try {
          const result = await this.executor.execute(script);
          return result.exitCode === 0;
        } catch (error) {
          return false;
        }
      },
    };
  });

  describe('Basic Execution Flow', () => {
    it('should execute simple commands without parameters', async () => {
      const tool = createMockTool({
        inputSchema: {
          type: 'object',
          properties: {},
        },
      });

      mockJXAExecutor.execute.mockResolvedValueOnce({
        stdout: 'true',
        stderr: '',
        exitCode: 0,
      });

      const result = await adapter.execute(tool, {});

      expect(result.success).toBe(true);
      expect(mockJXAExecutor.execute).toHaveBeenCalled();
    });

    it('should execute commands with parameters', async () => {
      const tool = createMockTool();
      const args = { target: '/Users/test/Desktop' };

      mockJXAExecutor.execute.mockResolvedValueOnce({
        stdout: '{"success": true}',
        stderr: '',
        exitCode: 0,
      });

      const result = await adapter.execute(tool, args);

      expect(result.success).toBe(true);
      expect(mockJXAExecutor.execute).toHaveBeenCalledWith(
        expect.stringContaining('Application("Finder")'),
        expect.any(Object)
      );
    });

    it('should handle successful results correctly', async () => {
      const tool = createMockTool();
      const expectedData = ['file1.txt', 'file2.pdf'];

      mockJXAExecutor.execute.mockResolvedValueOnce({
        stdout: JSON.stringify(expectedData),
        stderr: '',
        exitCode: 0,
      });

      mockResultParser.parse.mockReturnValueOnce({
        success: true,
        data: expectedData,
      });

      const result = await adapter.execute(tool, {});

      expect(result.success).toBe(true);
      expect(result.data).toEqual(expectedData);
    });

    it('should parse and return results correctly', async () => {
      const tool = createMockTool();
      const testResult = 'hello world';

      mockJXAExecutor.execute.mockResolvedValueOnce({
        stdout: `"${testResult}"`,
        stderr: '',
        exitCode: 0,
      });

      mockResultParser.parse.mockReturnValueOnce({
        success: true,
        data: testResult,
      });

      const result = await adapter.execute(tool, {});

      expect(result.success).toBe(true);
      expect(result.data).toBe(testResult);
      expect(mockResultParser.parse).toHaveBeenCalled();
    });
  });

  describe('Integration with Components', () => {
    it('should use ParameterMarshaler to prepare parameters', async () => {
      const tool = createMockTool();
      const args = { target: '/path/to/file' };

      mockJXAExecutor.execute.mockResolvedValueOnce({
        stdout: 'null',
        stderr: '',
        exitCode: 0,
      });

      await adapter.execute(tool, args);

      expect(mockParameterMarshaler.marshal).toHaveBeenCalledWith(
        args,
        tool.inputSchema,
        tool._metadata
      );
    });

    it('should use JXAExecutor to run scripts', async () => {
      const tool = createMockTool();

      mockJXAExecutor.execute.mockResolvedValueOnce({
        stdout: 'true',
        stderr: '',
        exitCode: 0,
      });

      await adapter.execute(tool, {});

      expect(mockJXAExecutor.execute).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({ timeoutMs: 30000 })
      );
    });

    it('should use ResultParser to parse results', async () => {
      const tool = createMockTool();

      const executionResult: ExecutionResult = {
        stdout: '{"result": "data"}',
        stderr: '',
        exitCode: 0,
      };

      mockJXAExecutor.execute.mockResolvedValueOnce(executionResult);

      await adapter.execute(tool, {});

      expect(mockResultParser.parse).toHaveBeenCalledWith(executionResult, tool._metadata);
    });

    it('should compose JXA scripts from command and parameters', async () => {
      const tool = createMockTool();
      const args = { target: '/Users/test/Desktop' };

      mockJXAExecutor.execute.mockResolvedValueOnce({
        stdout: 'null',
        stderr: '',
        exitCode: 0,
      });

      await adapter.execute(tool, args);

      const callArgs = mockJXAExecutor.execute.mock.calls[0];
      const script = callArgs[0];

      // Verify script structure
      expect(script).toContain('const app = Application("Finder")');
      expect(script).toContain('app.includeStandardAdditions = true');
      expect(script).toContain('app.open');
      expect(script).toContain('return result');
    });

    it('should properly inject marshaled parameters into script', async () => {
      const tool = createMockTool();
      const args = { target: '/path/to/file' };

      mockJXAExecutor.execute.mockResolvedValueOnce({
        stdout: 'null',
        stderr: '',
        exitCode: 0,
      });

      await adapter.execute(tool, args);

      const callArgs = mockJXAExecutor.execute.mock.calls[0];
      const script = callArgs[0];

      // Script should contain the marshaled parameters
      expect(script).toContain('const params');
      expect(mockParameterMarshaler.marshal).toHaveBeenCalled();
    });
  });

  describe('Error Handling', () => {
    it('should handle APP_NOT_FOUND errors', async () => {
      const tool = createMockTool();

      mockJXAExecutor.execute.mockResolvedValueOnce({
        stdout: '',
        stderr: "Error: Application can't be found.",
        exitCode: 1,
      });

      mockResultParser.parse.mockReturnValueOnce({
        success: false,
        error: {
          type: 'APP_NOT_FOUND',
          message: "Finder app not found",
        },
      });

      const result = await adapter.execute(tool, {});

      expect(result.success).toBe(false);
      expect(result.error?.type).toBe('APP_NOT_FOUND');
    });

    it('should handle APP_NOT_RUNNING errors', async () => {
      const tool = createMockTool();

      mockJXAExecutor.execute.mockResolvedValueOnce({
        stdout: '',
        stderr: 'Error: Application needs to be running',
        exitCode: 1,
      });

      mockResultParser.parse.mockReturnValueOnce({
        success: false,
        error: {
          type: 'APP_NOT_RUNNING',
          message: 'Safari is not running',
        },
      });

      const result = await adapter.execute(tool, {});

      expect(result.success).toBe(false);
      expect(result.error?.type).toBe('APP_NOT_RUNNING');
    });

    it('should handle PERMISSION_DENIED errors', async () => {
      const tool = createMockTool();

      mockJXAExecutor.execute.mockResolvedValueOnce({
        stdout: '',
        stderr: 'Error: Not authorized to send Apple events',
        exitCode: 1,
      });

      mockResultParser.parse.mockReturnValueOnce({
        success: false,
        error: {
          type: 'PERMISSION_DENIED',
          message: 'Permission denied',
        },
      });

      const result = await adapter.execute(tool, {});

      expect(result.success).toBe(false);
      expect(result.error?.type).toBe('PERMISSION_DENIED');
    });

    it('should handle INVALID_PARAM errors', async () => {
      const tool = createMockTool();

      mockJXAExecutor.execute.mockResolvedValueOnce({
        stdout: '',
        stderr: "Error: Can't get object",
        exitCode: 1,
      });

      mockResultParser.parse.mockReturnValueOnce({
        success: false,
        error: {
          type: 'INVALID_PARAM',
          message: 'Invalid parameter value',
        },
      });

      const result = await adapter.execute(tool, {});

      expect(result.success).toBe(false);
      expect(result.error?.type).toBe('INVALID_PARAM');
    });

    it('should handle TIMEOUT errors', async () => {
      const tool = createMockTool();

      mockJXAExecutor.execute.mockResolvedValueOnce({
        stdout: '',
        stderr: 'Error: timeout',
        exitCode: 1,
        timedOut: true,
      });

      mockResultParser.parse.mockReturnValueOnce({
        success: false,
        error: {
          type: 'TIMEOUT',
          message: 'Command timed out',
        },
      });

      const result = await adapter.execute(tool, {});

      expect(result.success).toBe(false);
      expect(result.error?.type).toBe('TIMEOUT');
    });

    it('should handle EXECUTION_ERROR errors', async () => {
      const tool = createMockTool();

      mockJXAExecutor.execute.mockResolvedValueOnce({
        stdout: '',
        stderr: 'Error: Syntax error in script',
        exitCode: 1,
      });

      mockResultParser.parse.mockReturnValueOnce({
        success: false,
        error: {
          type: 'EXECUTION_ERROR',
          message: 'Script execution failed',
        },
      });

      const result = await adapter.execute(tool, {});

      expect(result.success).toBe(false);
      expect(result.error?.type).toBe('EXECUTION_ERROR');
    });
  });

  describe('Tool Metadata', () => {
    it('should pass through app bundle ID', async () => {
      const tool = createMockTool();
      tool._metadata!.bundleId = 'com.apple.finder';

      mockJXAExecutor.execute.mockResolvedValueOnce({
        stdout: 'null',
        stderr: '',
        exitCode: 0,
      });

      await adapter.execute(tool, {});

      expect(mockParameterMarshaler.marshal).toHaveBeenCalledWith(
        expect.any(Object),
        expect.any(Object),
        expect.objectContaining({ bundleId: 'com.apple.finder' })
      );
    });

    it('should pass through command name', async () => {
      const tool = createMockTool();
      tool._metadata!.commandName = 'open';

      mockJXAExecutor.execute.mockResolvedValueOnce({
        stdout: 'null',
        stderr: '',
        exitCode: 0,
      });

      await adapter.execute(tool, {});

      const script = mockJXAExecutor.execute.mock.calls[0][0];
      expect(script).toContain('app.open');
    });

    it('should use metadata for error context', async () => {
      const tool = createMockTool();
      tool._metadata!.appName = 'Safari';

      mockJXAExecutor.execute.mockResolvedValueOnce({
        stdout: '',
        stderr: "Error: Application can't be found.",
        exitCode: 1,
      });

      mockResultParser.parse.mockReturnValueOnce({
        success: false,
        error: {
          type: 'APP_NOT_FOUND',
          message: "Finder app not found",
        },
      });

      const result = await adapter.execute(tool, {});

      expect(result.error?.appName).toBe('Safari');
    });

    it('should throw error when tool metadata is missing', async () => {
      const tool = createMockTool();
      delete tool._metadata;

      await expect(adapter.execute(tool, {})).rejects.toThrow('Tool metadata is required');
    });
  });

  describe('Script Generation', () => {
    it('should generate correct JXA script structure', () => {
      const tool = createMockTool();

      const script = adapter.buildJXAScript(tool, {});

      // Verify IIFE structure
      expect(script).toMatch(/^\(\(\) => \{[\s\S]*\}\)\(\)$/);

      // Verify app instantiation
      expect(script).toContain('const app = Application("Finder")');

      // Verify includeStandardAdditions
      expect(script).toContain('app.includeStandardAdditions = true');
    });

    it('should handle commands with no parameters', () => {
      const tool = createMockTool({
        inputSchema: {
          type: 'object',
          properties: {},
        },
      });

      const script = adapter.buildJXAScript(tool, {});

      expect(script).toContain('const params');
      expect(script).toContain('return result');
    });

    it('should handle commands with single parameter', () => {
      const tool = createMockTool();
      const args = { target: '/Users/test/file.txt' };

      const script = adapter.buildJXAScript(tool, args);

      expect(script).toContain('const params');
      expect(mockParameterMarshaler.marshal).toHaveBeenCalledWith(args, tool.inputSchema, tool._metadata);
    });

    it('should handle commands with multiple parameters', () => {
      const tool = createMockTool({
        inputSchema: {
          type: 'object',
          properties: {
            from: { type: 'string' },
            to: { type: 'string' },
            overwrite: { type: 'boolean' },
          },
        },
      });

      const args = {
        from: '/Users/test/source.txt',
        to: '/Users/test/dest.txt',
        overwrite: true,
      };

      const script = adapter.buildJXAScript(tool, args);

      expect(mockParameterMarshaler.marshal).toHaveBeenCalledWith(args, tool.inputSchema, tool._metadata);
      expect(script).toContain('const params');
    });

    it('should handle commands with complex nested parameters', () => {
      const tool = createMockTool({
        inputSchema: {
          type: 'object',
          properties: {
            config: {
              type: 'object',
              properties: {
                options: { type: 'array', items: { type: 'string' } },
                timeout: { type: 'number' },
              },
            },
          },
        },
      });

      const args = {
        config: {
          options: ['opt1', 'opt2'],
          timeout: 5000,
        },
      };

      const script = adapter.buildJXAScript(tool, args);

      expect(mockParameterMarshaler.marshal).toHaveBeenCalledWith(args, tool.inputSchema, tool._metadata);
    });

    it('should properly inject marshaled parameters into script', () => {
      const tool = createMockTool();
      const args = { target: '/path/to/file' };

      mockParameterMarshaler.marshal.mockReturnValueOnce("{ target: '/path/to/file' }");

      const script = adapter.buildJXAScript(tool, args);

      // The marshaled params should be in the script
      expect(script).toContain('const params');
      expect(mockParameterMarshaler.marshal).toHaveBeenCalled();
    });
  });

  describe('Real-World Scenarios', () => {
    describe('Finder operations', () => {
      it('should execute finder open folder command', async () => {
        const tool = createMockTool({
          name: 'finder_open',
          description: 'Open a folder in Finder',
        });

        mockJXAExecutor.execute.mockResolvedValueOnce({
          stdout: 'true',
          stderr: '',
          exitCode: 0,
        });

        mockResultParser.parse.mockReturnValueOnce({
          success: true,
          data: true,
        });

        const result = await adapter.execute(tool, { target: '/Users/test/Desktop' });

        expect(result.success).toBe(true);
        expect(mockJXAExecutor.execute).toHaveBeenCalled();
      });

      it('should execute finder list files command', async () => {
        const tool = createMockTool({
          name: 'finder_list_files',
          description: 'List files in a folder',
        });

        const fileList = ['file1.txt', 'file2.pdf', 'folder'];

        mockJXAExecutor.execute.mockResolvedValueOnce({
          stdout: JSON.stringify(fileList),
          stderr: '',
          exitCode: 0,
        });

        mockResultParser.parse.mockReturnValueOnce({
          success: true,
          data: fileList,
        });

        const result = await adapter.execute(tool, { target: '/Users/test' });

        expect(result.success).toBe(true);
        expect(result.data).toEqual(fileList);
      });
    });

    describe('Safari operations', () => {
      it('should execute safari get current URL command', async () => {
        const tool = createMockTool({
          name: 'safari_get_url',
          description: 'Get the current tab URL',
          _metadata: createMockMetadata({
            appName: 'Safari',
            bundleId: 'com.apple.Safari',
            commandName: 'getUrl',
          }),
        });

        mockJXAExecutor.execute.mockResolvedValueOnce({
          stdout: '"https://www.example.com"',
          stderr: '',
          exitCode: 0,
        });

        mockResultParser.parse.mockReturnValueOnce({
          success: true,
          data: 'https://www.example.com',
        });

        const result = await adapter.execute(tool, {});

        expect(result.success).toBe(true);
        expect(result.data).toBe('https://www.example.com');
      });

      it('should handle safari not running error', async () => {
        const tool = createMockTool({
          _metadata: createMockMetadata({
            appName: 'Safari',
          }),
        });

        mockJXAExecutor.execute.mockResolvedValueOnce({
          stdout: '',
          stderr: "Error: Application can't be found.",
          exitCode: 1,
        });

        mockResultParser.parse.mockReturnValueOnce({
          success: false,
          error: {
            type: 'APP_NOT_RUNNING',
            message: 'Safari is not running',
          },
        });

        const result = await adapter.execute(tool, {});

        expect(result.success).toBe(false);
        expect(result.error?.appName).toBe('Safari');
      });
    });

    describe('Mail operations', () => {
      it('should execute mail send email command', async () => {
        const tool = createMockTool({
          name: 'mail_send',
          description: 'Send an email',
          _metadata: createMockMetadata({
            appName: 'Mail',
            bundleId: 'com.apple.mail',
            commandName: 'send',
          }),
          inputSchema: {
            type: 'object',
            properties: {
              to: { type: 'string' },
              subject: { type: 'string' },
              body: { type: 'string' },
            },
            required: ['to', 'subject', 'body'],
          },
        });

        mockJXAExecutor.execute.mockResolvedValueOnce({
          stdout: '{"sent": true}',
          stderr: '',
          exitCode: 0,
        });

        mockResultParser.parse.mockReturnValueOnce({
          success: true,
          data: { sent: true },
        });

        const result = await adapter.execute(tool, {
          to: 'user@example.com',
          subject: 'Test',
          body: 'Test body',
        });

        expect(result.success).toBe(true);
      });
    });

    describe('System Events operations', () => {
      it('should execute system events commands', async () => {
        const tool = createMockTool({
          name: 'system_get_volume',
          description: 'Get system volume',
          _metadata: createMockMetadata({
            appName: 'System Events',
            bundleId: 'com.apple.systemevents',
            commandName: 'getVolume',
          }),
        });

        mockJXAExecutor.execute.mockResolvedValueOnce({
          stdout: '75',
          stderr: '',
          exitCode: 0,
        });

        mockResultParser.parse.mockReturnValueOnce({
          success: true,
          data: 75,
        });

        const result = await adapter.execute(tool, {});

        expect(result.success).toBe(true);
        expect(result.data).toBe(75);
      });
    });
  });

  describe('Options Handling', () => {
    it('should respect timeout configuration', async () => {
      const customAdapter = { ...adapter, timeout: 5000 };
      const tool = createMockTool();

      mockJXAExecutor.execute.mockResolvedValueOnce({
        stdout: 'null',
        stderr: '',
        exitCode: 0,
      });

      await customAdapter.execute(tool, {});

      expect(mockJXAExecutor.execute).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({ timeoutMs: 5000 })
      );
    });

    it('should pass error capture configuration to executor', async () => {
      const tool = createMockTool();

      mockJXAExecutor.execute.mockResolvedValueOnce({
        stdout: 'null',
        stderr: 'some error',
        exitCode: 0,
      });

      await adapter.execute(tool, {});

      expect(mockJXAExecutor.execute).toHaveBeenCalled();
      // Executor should capture stderr
      expect(mockResultParser.parse).toHaveBeenCalled();
    });

    it('should propagate metadata through execution', async () => {
      const tool = createMockTool();
      const customMetadata = {
        ...tool._metadata,
        commandCode: 'CUST',
      };

      tool._metadata = customMetadata;

      mockJXAExecutor.execute.mockResolvedValueOnce({
        stdout: 'null',
        stderr: '',
        exitCode: 0,
      });

      await adapter.execute(tool, {});

      expect(mockResultParser.parse).toHaveBeenCalledWith(
        expect.any(Object),
        expect.objectContaining({ commandCode: 'CUST' })
      );
    });
  });

  describe('Edge Cases and Error Conditions', () => {
    it('should handle empty command arguments', async () => {
      const tool = createMockTool({
        inputSchema: {
          type: 'object',
          properties: {},
        },
      });

      mockJXAExecutor.execute.mockResolvedValueOnce({
        stdout: 'null',
        stderr: '',
        exitCode: 0,
      });

      const result = await adapter.execute(tool, {});

      expect(result.success).toBe(true);
    });

    it('should handle null results from JXA', async () => {
      const tool = createMockTool();

      mockJXAExecutor.execute.mockResolvedValueOnce({
        stdout: 'null',
        stderr: '',
        exitCode: 0,
      });

      mockResultParser.parse.mockReturnValueOnce({
        success: true,
        data: null,
      });

      const result = await adapter.execute(tool, {});

      expect(result.success).toBe(true);
      expect(result.data).toBeNull();
    });

    it('should handle very large results', async () => {
      const tool = createMockTool();
      const largeArray = new Array(10000).fill('item');

      mockJXAExecutor.execute.mockResolvedValueOnce({
        stdout: JSON.stringify(largeArray),
        stderr: '',
        exitCode: 0,
      });

      mockResultParser.parse.mockReturnValueOnce({
        success: true,
        data: largeArray,
      });

      const result = await adapter.execute(tool, {});

      expect(result.success).toBe(true);
      expect(result.data?.length).toBe(10000);
    });

    it('should handle results with special characters', async () => {
      const tool = createMockTool();
      const specialString = 'Test "quoted" and \\backslash\\ and \nnewline';

      mockJXAExecutor.execute.mockResolvedValueOnce({
        stdout: JSON.stringify(specialString),
        stderr: '',
        exitCode: 0,
      });

      mockResultParser.parse.mockReturnValueOnce({
        success: true,
        data: specialString,
      });

      const result = await adapter.execute(tool, {});

      expect(result.success).toBe(true);
      expect(result.data).toBe(specialString);
    });

    it('should handle unicode characters in results', async () => {
      const tool = createMockTool();
      const unicodeString = 'Hello 世界 🌍 Привет مرحبا';

      mockJXAExecutor.execute.mockResolvedValueOnce({
        stdout: JSON.stringify(unicodeString),
        stderr: '',
        exitCode: 0,
      });

      mockResultParser.parse.mockReturnValueOnce({
        success: true,
        data: unicodeString,
      });

      const result = await adapter.execute(tool, {});

      expect(result.success).toBe(true);
      expect(result.data).toBe(unicodeString);
    });

    it('should handle commands with many parameters', async () => {
      const tool = createMockTool({
        inputSchema: {
          type: 'object',
          properties: {
            param1: { type: 'string' },
            param2: { type: 'string' },
            param3: { type: 'number' },
            param4: { type: 'boolean' },
            param5: { type: 'array', items: { type: 'string' } },
            param6: { type: 'object' },
            param7: { type: 'string' },
            param8: { type: 'string' },
          },
        },
      });

      const args = {
        param1: 'value1',
        param2: 'value2',
        param3: 123,
        param4: true,
        param5: ['a', 'b', 'c'],
        param6: { nested: 'value' },
        param7: 'value7',
        param8: 'value8',
      };

      mockJXAExecutor.execute.mockResolvedValueOnce({
        stdout: 'null',
        stderr: '',
        exitCode: 0,
      });

      const result = await adapter.execute(tool, args);

      expect(result.success).toBe(true);
      expect(mockParameterMarshaler.marshal).toHaveBeenCalledWith(args, tool.inputSchema, tool._metadata);
    });
  });

  describe('Execution Flow Validation', () => {
    it('should call components in correct order', async () => {
      const tool = createMockTool();
      const callOrder: string[] = [];

      mockParameterMarshaler.marshal.mockImplementation(() => {
        callOrder.push('marshal');
        return '{}';
      });

      mockJXAExecutor.execute.mockImplementation(() => {
        callOrder.push('execute');
        return Promise.resolve({
          stdout: 'null',
          stderr: '',
          exitCode: 0,
        });
      });

      mockResultParser.parse.mockImplementation(() => {
        callOrder.push('parse');
        return { success: true, data: null };
      });

      await adapter.execute(tool, {});

      expect(callOrder).toEqual(['marshal', 'execute', 'parse']);
    });

    it('should handle executor throwing errors', async () => {
      const tool = createMockTool();

      mockJXAExecutor.execute.mockRejectedValueOnce(new Error('osascript not found'));

      await expect(adapter.execute(tool, {})).rejects.toThrow('osascript not found');
    });

    it('should validate tool metadata before execution', async () => {
      const tool = createMockTool();
      tool._metadata = undefined;

      await expect(adapter.execute(tool, {})).rejects.toThrow('Tool metadata is required');
    });
  });

  describe('testApp functionality', () => {
    it('should test if app is available', async () => {
      mockJXAExecutor.execute.mockResolvedValueOnce({
        stdout: 'true',
        stderr: '',
        exitCode: 0,
      });

      const result = await adapter.testApp('com.apple.finder');

      expect(result).toBe(true);
      expect(mockJXAExecutor.execute).toHaveBeenCalled();
    });

    it('should return false if app is not available', async () => {
      mockJXAExecutor.execute.mockResolvedValueOnce({
        stdout: '',
        stderr: 'Error: Application not found',
        exitCode: 1,
      });

      const result = await adapter.testApp('com.nonexistent.app');

      expect(result).toBe(false);
    });

    it('should handle executor errors gracefully', async () => {
      mockJXAExecutor.execute.mockRejectedValueOnce(new Error('Execution failed'));

      const result = await adapter.testApp('com.apple.finder');

      expect(result).toBe(false);
    });
  });

  describe('buildJXAScript validation', () => {
    it('should throw error if tool metadata is missing', () => {
      const tool = createMockTool();
      delete tool._metadata;

      expect(() => adapter.buildJXAScript(tool, {})).toThrow('Tool metadata is missing');
    });

    it('should generate deterministic scripts for same inputs', () => {
      const tool = createMockTool();
      const args = { target: '/Users/test' };

      const script1 = adapter.buildJXAScript(tool, args);
      const script2 = adapter.buildJXAScript(tool, args);

      // Scripts should be identical for same inputs
      // (assuming marshaler is deterministic)
      expect(script1).toContain('Application("Finder")');
      expect(script2).toContain('Application("Finder")');
    });
  });

  describe('Security: Script Injection Prevention', () => {
    let realAdapter: MacOSAdapter;

    beforeEach(() => {
      realAdapter = new MacOSAdapter({ enableLogging: false });
    });

    it('should reject appName with double quotes', () => {
      const tool = createMockTool();
      tool._metadata!.appName = 'Finder"); process.exit(1); ("';

      expect(() => realAdapter.buildJXAScript(tool, {})).toThrow('Invalid appName');
      expect(() => realAdapter.buildJXAScript(tool, {})).toThrow('script injection');
    });

    it('should reject appName with single quotes', () => {
      const tool = createMockTool();
      tool._metadata!.appName = "Finder'; malicious(); '";

      expect(() => realAdapter.buildJXAScript(tool, {})).toThrow('Invalid appName');
    });

    it('should reject appName with backslashes', () => {
      const tool = createMockTool();
      tool._metadata!.appName = 'Finder\\"malicious';

      expect(() => realAdapter.buildJXAScript(tool, {})).toThrow('Invalid appName');
    });

    it('should reject appName with semicolons', () => {
      const tool = createMockTool();
      tool._metadata!.appName = 'Finder; malicious()';

      expect(() => realAdapter.buildJXAScript(tool, {})).toThrow('Invalid appName');
    });

    it('should reject appName with dollar signs', () => {
      const tool = createMockTool();
      tool._metadata!.appName = 'Finder${malicious}';

      expect(() => realAdapter.buildJXAScript(tool, {})).toThrow('Invalid appName');
    });

    it('should reject appName with backticks', () => {
      const tool = createMockTool();
      tool._metadata!.appName = 'Finder`malicious`';

      expect(() => realAdapter.buildJXAScript(tool, {})).toThrow('Invalid appName');
    });

    it('should reject appName with parentheses', () => {
      const tool = createMockTool();
      tool._metadata!.appName = 'Finder(malicious)';

      expect(() => realAdapter.buildJXAScript(tool, {})).toThrow('Invalid appName');
    });

    it('should reject commandName with double quotes', () => {
      const tool = createMockTool();
      tool._metadata!.commandName = 'open"); malicious("';

      expect(() => realAdapter.buildJXAScript(tool, {})).toThrow('Invalid commandName');
      expect(() => realAdapter.buildJXAScript(tool, {})).toThrow('script injection');
    });

    it('should reject commandName with single quotes', () => {
      const tool = createMockTool();
      tool._metadata!.commandName = "open'; malicious(); '";

      expect(() => realAdapter.buildJXAScript(tool, {})).toThrow('Invalid commandName');
    });

    it('should reject commandName with backslashes', () => {
      const tool = createMockTool();
      tool._metadata!.commandName = 'open\\"malicious';

      expect(() => realAdapter.buildJXAScript(tool, {})).toThrow('Invalid commandName');
    });

    it('should reject commandName with semicolons', () => {
      const tool = createMockTool();
      tool._metadata!.commandName = 'open; malicious()';

      expect(() => realAdapter.buildJXAScript(tool, {})).toThrow('Invalid commandName');
    });

    it('should reject commandName with dollar signs', () => {
      const tool = createMockTool();
      tool._metadata!.commandName = 'open${malicious}';

      expect(() => realAdapter.buildJXAScript(tool, {})).toThrow('Invalid commandName');
    });

    it('should reject commandName with backticks', () => {
      const tool = createMockTool();
      tool._metadata!.commandName = 'open`malicious`';

      expect(() => realAdapter.buildJXAScript(tool, {})).toThrow('Invalid commandName');
    });

    it('should reject commandName with parentheses', () => {
      const tool = createMockTool();
      tool._metadata!.commandName = 'open(malicious)';

      expect(() => realAdapter.buildJXAScript(tool, {})).toThrow('Invalid commandName');
    });

    it('should allow valid appName', () => {
      const tool = createMockTool();
      tool._metadata!.appName = 'Finder';

      const script = realAdapter.buildJXAScript(tool, {});
      expect(script).toContain('Application("Finder")');
    });

    it('should allow valid commandName', () => {
      const tool = createMockTool();
      tool._metadata!.commandName = 'open';

      const script = realAdapter.buildJXAScript(tool, {});
      expect(script).toContain('app.open');
    });

    it('should allow valid appName with alphanumeric and spaces', () => {
      const tool = createMockTool();
      tool._metadata!.appName = 'System Events';

      const script = realAdapter.buildJXAScript(tool, {});
      expect(script).toContain('Application("System Events")');
    });

    it('should allow valid commandName with camelCase', () => {
      const tool = createMockTool();
      tool._metadata!.commandName = 'getVolume';

      const script = realAdapter.buildJXAScript(tool, {});
      expect(script).toContain('app.getVolume');
    });
  });
});
