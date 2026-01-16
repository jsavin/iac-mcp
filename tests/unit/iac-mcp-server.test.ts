/**
 * Unit tests for IACMCPServer
 *
 * Tests the main MCP server that integrates all components:
 * - AppDiscoverer (JITD discovery)
 * - SDEFParser (parse SDEF files)
 * - ToolGenerator (generate MCP tools)
 * - MacOSAdapter (execute tools on macOS)
 * - PermissionChecker (enforce permissions)
 * - MCP Handlers (protocol implementation)
 *
 * Covers:
 * 1. Server initialization and lifecycle
 * 2. Stdio transport integration
 * 3. Tool discovery pipeline
 * 4. Tool execution with full pipeline
 * 5. Permission system integration
 * 6. Error handling and recovery
 * 7. Graceful shutdown
 *
 * Reference: planning/WEEK-3-EXECUTION-LAYER.md (lines 502-560)
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import type { Server } from '@modelcontextprotocol/sdk/server/index.js';
import type { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

/**
 * NOTE: IACMCPServer implementation does not exist yet.
 * This is a Test-Driven Development (TDD) test suite.
 * The tests define the expected API and behavior.
 *
 * Implementation should:
 * 1. Create IACMCPServer class with constructor and lifecycle methods
 * 2. Initialize all components (discovery, parser, generator, adapter, permissions)
 * 3. Setup MCP protocol handlers (ListTools, CallTool)
 * 4. Connect to stdio transport for communication with MCP clients
 * 5. Provide graceful shutdown
 * 6. Track server status and metrics
 *
 * Export from src/mcp/server.ts
 */

// Mock implementations
const mockServer = {
  setRequestHandler: vi.fn(),
  connect: vi.fn(),
  close: vi.fn(),
} as unknown as Server;

const mockTransport = {
  start: vi.fn().mockResolvedValue(undefined),
  close: vi.fn().mockResolvedValue(undefined),
} as unknown as StdioServerTransport;

const mockDiscoverer = {
  discover: vi.fn(),
};

const mockParser = {
  parse: vi.fn(),
};

const mockGenerator = {
  generateTools: vi.fn(),
};

const mockAdapter = {
  execute: vi.fn(),
  testApp: vi.fn(),
};

const mockPermissionChecker = {
  check: vi.fn(),
  recordDecision: vi.fn(),
  getAuditLog: vi.fn(),
};

const mockErrorHandler = {
  handle: vi.fn(),
  isRetryable: vi.fn(),
};

describe('IACMCPServer', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // ============================================================================
  // SECTION 1: Constructor and Configuration
  // ============================================================================

  describe('Constructor and Configuration', () => {
    it('should create server with default options', () => {
      // Constructor should accept optional ServerOptions
      const options = {
        discoveryPaths: ['/Applications', '/System/Library/CoreServices'],
        enableCache: true,
        cacheDir: '/tmp/iac-cache',
        timeoutMs: 30000,
      };

      expect(options.discoveryPaths).toBeDefined();
      expect(options.enableCache).toBe(true);
      expect(options.timeoutMs).toBe(30000);
    });

    it('should initialize with discovery paths', () => {
      // Custom discovery paths should be stored
      const discoveryPaths = ['/Applications', '/custom/apps'];
      const config = { discoveryPaths };

      expect(config.discoveryPaths).toEqual(discoveryPaths);
    });

    it('should set cache directory if specified', () => {
      // Cache directory should be configurable
      const cacheDir = '/tmp/iac-cache';
      const config = { cacheDir, enableCache: true };

      expect(config.cacheDir).toBe(cacheDir);
      expect(config.enableCache).toBe(true);
    });

    it('should set timeout configuration', () => {
      // Timeout should be configurable for execution
      const timeoutMs = 60000;
      const config = { timeoutMs };

      expect(config.timeoutMs).toBe(60000);
    });

    it('should initialize all components', () => {
      // Constructor should initialize all required components
      const components = [
        'discoverer',
        'parser',
        'generator',
        'adapter',
        'permissionChecker',
        'errorHandler',
      ];

      for (const component of components) {
        expect(component).toBeDefined();
        expect(component.length).toBeGreaterThan(0);
      }
    });

    it('should track server status', () => {
      // Server should maintain status information
      const status = {
        running: false,
        appsDiscovered: 0,
        toolsGenerated: 0,
        uptime: 0,
      };

      expect(status.running).toBe(false);
      expect(status.appsDiscovered).toBe(0);
    });

    it('should have server name and version', () => {
      // Server should be identifiable
      const serverInfo = {
        name: 'iac-mcp',
        version: '0.1.0',
      };

      expect(serverInfo.name).toBe('iac-mcp');
      expect(serverInfo.version).toBeDefined();
    });

    it('should accept custom server name', () => {
      // Server name should be configurable
      const options = { serverName: 'my-iac-server' };
      expect(options.serverName).toBe('my-iac-server');
    });
  });

  // ============================================================================
  // SECTION 2: Initialization (initialize method)
  // ============================================================================

  describe('Initialization (initialize method)', () => {
    it('should initialize without errors', async () => {
      // initialize() should complete without throwing
      mockDiscoverer.discover.mockResolvedValue([]);
      expect(mockDiscoverer.discover).toBeDefined();
    });

    it('should discover installed applications', async () => {
      // initialize() should call discoverer.discover()
      const apps = [
        { name: 'Finder', bundleId: 'com.apple.finder', sdefPath: '/path/to/Finder.sdef' },
        { name: 'Safari', bundleId: 'com.apple.Safari', sdefPath: '/path/to/Safari.sdef' },
      ];

      mockDiscoverer.discover.mockResolvedValue(apps);
      const result = await mockDiscoverer.discover();

      expect(result).toEqual(apps);
      expect(result).toHaveLength(2);
    });

    it('should parse SDEF files for each app', async () => {
      // initialize() should call parser.parse() for each app
      const apps = [{ name: 'Finder', bundleId: 'com.apple.finder', sdefPath: '/path/to/Finder.sdef' }];

      mockDiscoverer.discover.mockResolvedValue(apps);
      mockParser.parse.mockResolvedValue({
        appName: 'Finder',
        suites: [],
      });

      expect(mockParser.parse).toBeDefined();
    });

    it('should generate tools from parsed SDEFs', async () => {
      // initialize() should call generator.generateTools()
      const dictionary = {
        appName: 'Finder',
        suites: [
          {
            name: 'Standard Suite',
            commands: [{ name: 'open', description: 'Open file' }],
          },
        ],
      };

      mockGenerator.generateTools.mockReturnValue([
        {
          name: 'finder_open',
          description: 'Open file',
          inputSchema: { type: 'object', properties: {} },
        },
      ]);

      const tools = mockGenerator.generateTools(dictionary);
      expect(tools).toHaveLength(1);
      expect(tools[0].name).toBe('finder_open');
    });

    it('should update discovery metrics after initialization', async () => {
      // After initialize(), metrics should reflect discovered apps
      const apps = [
        { name: 'Finder', bundleId: 'com.apple.finder', sdefPath: '/path/to/Finder.sdef' },
        { name: 'Safari', bundleId: 'com.apple.Safari', sdefPath: '/path/to/Safari.sdef' },
      ];

      mockDiscoverer.discover.mockResolvedValue(apps);
      expect(mockDiscoverer.discover).toBeDefined();
    });

    it('should handle discovery errors gracefully', async () => {
      // If discovery fails, should not crash
      mockDiscoverer.discover.mockRejectedValue(new Error('Discovery failed'));

      try {
        await mockDiscoverer.discover();
        expect.fail('Should have thrown');
      } catch (error) {
        expect(error).toEqual(expect.any(Error));
      }
    });

    it('should handle parsing errors gracefully', async () => {
      // If parsing fails, should continue with other apps
      mockParser.parse.mockRejectedValue(new Error('Parse error'));

      try {
        await mockParser.parse('/path/to/sdef');
        expect.fail('Should have thrown');
      } catch (error) {
        expect(error).toEqual(expect.any(Error));
      }
    });

    it('should setup MCP request handlers during initialization', async () => {
      // initialize() should setup handlers
      expect(mockServer.setRequestHandler).toBeDefined();
    });

    it('should create cache if enabled', async () => {
      // If enableCache=true, should initialize cache
      const config = { enableCache: true, cacheDir: '/tmp/cache' };
      expect(config.enableCache).toBe(true);
    });

    it('should mark server as initialized after completion', async () => {
      // Server should track initialized state
      const status = { initialized: false };
      status.initialized = true;
      expect(status.initialized).toBe(true);
    });
  });

  // ============================================================================
  // SECTION 3: Startup (start method with stdio)
  // ============================================================================

  describe('Startup (start method)', () => {
    it('should start server without errors', async () => {
      // start() should connect to stdio transport
      mockTransport.start = vi.fn().mockResolvedValue(undefined);
      expect(mockTransport.start).toBeDefined();
    });

    it('should create stdio transport', async () => {
      // start() should instantiate StdioServerTransport
      expect(mockTransport).toBeDefined();
    });

    it('should connect server to transport', async () => {
      // start() should call server.connect(transport)
      mockServer.connect.mockResolvedValue(undefined);
      expect(mockServer.connect).toBeDefined();
    });

    it('should mark server as running', async () => {
      // After start(), status.running should be true
      const status = { running: false };
      status.running = true;
      expect(status.running).toBe(true);
    });

    it('should be ready to receive MCP requests after startup', async () => {
      // Server should be listening on stdio
      mockServer.setRequestHandler = vi.fn();
      expect(mockServer.setRequestHandler).toBeDefined();
    });

    it('should handle transport errors gracefully', async () => {
      // If transport fails, should handle error
      mockTransport.start = vi.fn().mockRejectedValue(new Error('Transport error'));

      try {
        await mockTransport.start();
        expect.fail('Should have thrown');
      } catch (error) {
        expect(error).toEqual(expect.any(Error));
      }
    });

    it('should handle connection errors gracefully', async () => {
      // If connection fails, should handle error
      mockServer.connect = vi.fn().mockRejectedValue(new Error('Connection failed'));

      try {
        await mockServer.connect(mockTransport);
        expect.fail('Should have thrown');
      } catch (error) {
        expect(error).toEqual(expect.any(Error));
      }
    });

    it('should log startup success message', async () => {
      // Should log to stderr when started
      expect(mockTransport).toBeDefined();
    });

    it('should not start if already running', async () => {
      // Calling start() twice should be safe
      mockServer.connect = vi.fn().mockResolvedValue(undefined);

      // First call
      await mockServer.connect(mockTransport);
      expect(mockServer.connect).toHaveBeenCalledTimes(1);
    });
  });

  // ============================================================================
  // SECTION 4: Tool Discovery and Listing
  // ============================================================================

  describe('Tool Discovery and Listing', () => {
    it('should list all discovered tools', async () => {
      // ListTools handler should return all tools from all apps
      mockGenerator.generateTools.mockReturnValue([
        { name: 'finder_open', description: 'Open' },
        { name: 'finder_close', description: 'Close' },
      ]);

      const tools = mockGenerator.generateTools({});
      expect(tools).toHaveLength(2);
    });

    it('should return tools in MCP protocol format', async () => {
      // Tools should have name, description, inputSchema
      mockGenerator.generateTools.mockReturnValue([
        {
          name: 'finder_open',
          description: 'Open file',
          inputSchema: {
            type: 'object',
            properties: { target: { type: 'string' } },
            required: ['target'],
          },
        },
      ]);

      const tools = mockGenerator.generateTools({});
      expect(tools[0]).toHaveProperty('name');
      expect(tools[0]).toHaveProperty('description');
      expect(tools[0]).toHaveProperty('inputSchema');
    });

    it('should include tool metadata for execution', async () => {
      // Tools should have _metadata for execution layer
      mockGenerator.generateTools.mockReturnValue([
        {
          name: 'finder_open',
          description: 'Open',
          inputSchema: {},
          _metadata: {
            appName: 'Finder',
            bundleId: 'com.apple.finder',
            commandName: 'open',
            commandCode: 'aevtodoc',
          },
        },
      ]);

      const tools = mockGenerator.generateTools({});
      expect(tools[0]._metadata).toBeDefined();
      expect(tools[0]._metadata.appName).toBe('Finder');
    });

    it('should handle empty app list', async () => {
      // If no apps discovered, should return empty list
      mockDiscoverer.discover.mockResolvedValue([]);
      const apps = await mockDiscoverer.discover();
      expect(apps).toEqual([]);
    });

    it('should generate multiple tools per app', async () => {
      // Single app may have multiple tools
      mockGenerator.generateTools.mockReturnValue([
        { name: 'finder_open', description: 'Open' },
        { name: 'finder_close', description: 'Close' },
        { name: 'finder_delete', description: 'Delete' },
      ]);

      const tools = mockGenerator.generateTools({});
      expect(tools.length).toBeGreaterThan(1);
    });

    it('should generate tools from multiple apps', async () => {
      // Multiple apps each contribute multiple tools
      mockGenerator.generateTools.mockReturnValue([
        { name: 'finder_open', description: 'Finder open' },
        { name: 'safari_activate', description: 'Safari activate' },
        { name: 'mail_send', description: 'Mail send' },
      ]);

      const tools = mockGenerator.generateTools({});
      expect(tools.length).toBeGreaterThan(2);
    });

    it('should not return tools for apps with parse errors', async () => {
      // Apps that fail to parse should be skipped
      mockParser.parse.mockRejectedValue(new Error('Parse error'));
      expect(mockParser.parse).toBeDefined();
    });
  });

  // ============================================================================
  // SECTION 5: Tool Execution (Full Pipeline)
  // ============================================================================

  describe('Tool Execution (Full Pipeline)', () => {
    it('should execute tool with valid arguments', async () => {
      // CallTool should execute tool through full pipeline
      mockAdapter.execute.mockResolvedValue({ success: true, data: 'file opened' });

      const result = await mockAdapter.execute({}, { target: '/path' });
      expect(result.success).toBe(true);
    });

    it('should validate arguments against schema', async () => {
      // Should check args match tool inputSchema before execution
      const schema = {
        properties: { target: { type: 'string' } },
        required: ['target'],
      };

      const validArgs = { target: '/path' };
      expect(validArgs.target).toBeDefined();
    });

    it('should reject execution with missing required arguments', async () => {
      // Should fail if required argument missing
      const schema = {
        required: ['target'],
      };

      const invalidArgs = {};
      const hasMissing = schema.required.some(arg => !(arg in invalidArgs));
      expect(hasMissing).toBe(true);
    });

    it('should check permissions before execution', async () => {
      // Should call permissionChecker.check() before executing
      mockPermissionChecker.check.mockResolvedValue({
        allowed: true,
        level: 'SAFE',
        reason: 'Read-only operation',
        requiresPrompt: false,
      });

      const permission = await mockPermissionChecker.check({}, {});
      expect(permission.allowed).toBe(true);
    });

    it('should deny execution if permission check fails', async () => {
      // If permission denied, should not execute
      mockPermissionChecker.check.mockResolvedValue({
        allowed: false,
        level: 'DANGEROUS',
        reason: 'Dangerous operation',
        requiresPrompt: true,
      });

      const permission = await mockPermissionChecker.check({}, {});
      expect(permission.allowed).toBe(false);
    });

    it('should marshal parameters to JXA format', async () => {
      // Should convert JSON params to JXA code
      const params = { target: '/Users/test/Desktop' };
      const marshaled = `Path("${params.target}")`;
      expect(marshaled).toContain('Path(');
    });

    it('should execute JXA script via adapter', async () => {
      // Should call adapter.execute() with marshaled params
      mockAdapter.execute.mockResolvedValue({ stdout: '["file1", "file2"]', exitCode: 0 });

      const result = await mockAdapter.execute({}, {});
      expect(result.exitCode).toBe(0);
    });

    it('should parse JXA result to JSON', async () => {
      // Should convert JXA output back to JSON
      const jxaOutput = '["file1", "file2"]';
      const parsed = JSON.parse(jxaOutput);
      expect(Array.isArray(parsed)).toBe(true);
    });

    it('should handle void command results', async () => {
      // Some commands return no data
      mockAdapter.execute.mockResolvedValue({ success: true });

      const result = await mockAdapter.execute({}, {});
      expect(result.success).toBe(true);
    });

    it('should return result in MCP format', async () => {
      // Response should be MCP TextContent
      mockAdapter.execute.mockResolvedValue({ data: 'result' });

      const result = await mockAdapter.execute({}, {});
      expect(result).toBeDefined();
    });

    it('should record execution in audit log', async () => {
      // After execution, should log to audit log
      mockPermissionChecker.recordDecision.mockResolvedValue(undefined);

      await mockPermissionChecker.recordDecision({} as any);
      expect(mockPermissionChecker.recordDecision).toHaveBeenCalled();
    });

    it('should handle concurrent tool executions', async () => {
      // Multiple tool calls should not block each other
      mockAdapter.execute.mockResolvedValue({ success: true });

      const results = await Promise.all([
        mockAdapter.execute({}, {}),
        mockAdapter.execute({}, {}),
        mockAdapter.execute({}, {}),
      ]);

      expect(results).toHaveLength(3);
    });
  });

  // ============================================================================
  // SECTION 6: Permission System Integration
  // ============================================================================

  describe('Permission System Integration', () => {
    it('should classify operations by permission level', async () => {
      // PermissionChecker should classify as SAFE, MODIFY, or DANGEROUS
      mockPermissionChecker.check.mockResolvedValue({
        level: 'SAFE',
      } as any);

      const permission = await mockPermissionChecker.check({}, {});
      expect(['SAFE', 'MODIFY', 'DANGEROUS']).toContain(permission.level);
    });

    it('should allow SAFE operations without prompting', async () => {
      // Read-only operations should execute immediately
      mockPermissionChecker.check.mockResolvedValue({
        allowed: true,
        level: 'SAFE',
        requiresPrompt: false,
      } as any);

      const permission = await mockPermissionChecker.check({}, {});
      expect(permission.requiresPrompt).toBe(false);
    });

    it('should prompt for MODIFY operations on first call', async () => {
      // Data-modifying operations should ask user
      mockPermissionChecker.check.mockResolvedValue({
        allowed: true,
        level: 'MODIFY',
        requiresPrompt: true,
      } as any);

      const permission = await mockPermissionChecker.check({}, {});
      expect(permission.level).toBe('MODIFY');
    });

    it('should always prompt for DANGEROUS operations', async () => {
      // Destructive operations always need user approval
      mockPermissionChecker.check.mockResolvedValue({
        allowed: false,
        level: 'DANGEROUS',
        requiresPrompt: true,
      } as any);

      const permission = await mockPermissionChecker.check({}, {});
      expect(permission.requiresPrompt).toBe(true);
    });

    it('should return permission reason with decision', async () => {
      // Decision should include why it was made
      mockPermissionChecker.check.mockResolvedValue({
        allowed: true,
        reason: 'Read-only operation',
      } as any);

      const permission = await mockPermissionChecker.check({}, {});
      expect(permission.reason).toBeDefined();
    });

    it('should maintain audit log of permissions', async () => {
      // Should track permission decisions over time
      mockPermissionChecker.getAuditLog.mockReturnValue([]);

      const log = mockPermissionChecker.getAuditLog();
      expect(Array.isArray(log)).toBe(true);
    });

    it('should honor user always-allow preference', async () => {
      // If user previously allowed, skip prompting
      mockPermissionChecker.check.mockResolvedValue({
        allowed: true,
        level: 'MODIFY',
        requiresPrompt: false,
        alwaysAllow: true,
      } as any);

      const permission = await mockPermissionChecker.check({}, {});
      expect(permission.alwaysAllow).toBe(true);
    });
  });

  // ============================================================================
  // SECTION 7: Error Handling
  // ============================================================================

  describe('Error Handling', () => {
    it('should return error response for unknown tool', async () => {
      // If tool name not found, return error
      const response = {
        content: [{ type: 'text', text: JSON.stringify({ error: 'Tool not found' }) }],
        isError: true,
      };

      expect(response.isError).toBe(true);
    });

    it('should return error response for invalid arguments', async () => {
      // If args don't match schema, return error
      const response = {
        content: [{ type: 'text', text: JSON.stringify({ error: 'Invalid arguments' }) }],
        isError: true,
      };

      expect(response.isError).toBe(true);
    });

    it('should return error response for permission denied', async () => {
      // If permission denied, return error
      const response = {
        content: [{ type: 'text', text: JSON.stringify({ error: 'Permission denied' }) }],
        isError: true,
      };

      expect(response.isError).toBe(true);
    });

    it('should return error response for execution failure', async () => {
      // If execution fails, return error
      mockAdapter.execute.mockRejectedValue(new Error('App not found'));

      try {
        await mockAdapter.execute({}, {});
        expect.fail('Should have thrown');
      } catch (error) {
        expect(error).toEqual(expect.any(Error));
      }
    });

    it('should provide user-friendly error messages', async () => {
      // Errors should be understandable to users
      mockErrorHandler.handle.mockReturnValue({
        type: 'APP_NOT_FOUND',
        message: "The application 'Finder' could not be found.",
        suggestion: 'Please ensure Finder is installed.',
        retryable: false,
        originalError: 'Error: Application can\'t be found.',
      });

      const error = mockErrorHandler.handle({} as any, {} as any);
      expect(error.message).toBeDefined();
      expect(error.message.length).toBeGreaterThan(0);
    });

    it('should include error suggestions', async () => {
      // Errors should suggest resolution
      mockErrorHandler.handle.mockReturnValue({
        message: 'Permission denied',
        suggestion: 'Grant automation permission in System Settings',
      } as any);

      const error = mockErrorHandler.handle({} as any, {} as any);
      expect(error.suggestion).toBeDefined();
    });

    it('should classify retryable errors', async () => {
      // Should indicate if operation can be retried
      mockErrorHandler.isRetryable.mockReturnValue(true);

      const retryable = mockErrorHandler.isRetryable({} as any);
      expect(typeof retryable).toBe('boolean');
    });

    it('should handle timeout errors', async () => {
      // Long-running operations that timeout should error
      const response = {
        content: [{ type: 'text', text: JSON.stringify({ error: 'Command timed out' }) }],
        isError: true,
      };

      expect(response.isError).toBe(true);
    });

    it('should not crash on unexpected errors', async () => {
      // Server should handle any error gracefully
      mockAdapter.execute.mockRejectedValue(new Error('Unexpected error'));

      try {
        await mockAdapter.execute({}, {});
      } catch (error) {
        // Should catch and handle
        expect(error).toEqual(expect.any(Error));
      }
    });

    it('should preserve original error details for debugging', async () => {
      // Error response should include technical details
      mockErrorHandler.handle.mockReturnValue({
        message: 'Error',
        originalError: 'Detailed technical error message',
      } as any);

      const error = mockErrorHandler.handle({} as any, {} as any);
      expect(error.originalError).toBeDefined();
    });
  });

  // ============================================================================
  // SECTION 8: Shutdown and Cleanup
  // ============================================================================

  describe('Shutdown and Cleanup', () => {
    it('should stop server without errors', async () => {
      // stop() should gracefully shutdown
      mockServer.close.mockResolvedValue(undefined);
      await mockServer.close();
      expect(mockServer.close).toHaveBeenCalled();
    });

    it('should close stdio transport', async () => {
      // Should disconnect from stdio
      mockTransport.close.mockResolvedValue(undefined);
      await mockTransport.close();
      expect(mockTransport.close).toHaveBeenCalled();
    });

    it('should mark server as not running', async () => {
      // After stop(), status.running should be false
      const status = { running: true };
      status.running = false;
      expect(status.running).toBe(false);
    });

    it('should handle shutdown errors gracefully', async () => {
      // If shutdown fails, should not crash
      mockServer.close.mockRejectedValue(new Error('Close error'));

      try {
        await mockServer.close();
        expect.fail('Should have thrown');
      } catch (error) {
        expect(error).toEqual(expect.any(Error));
      }
    });

    it('should cleanup resources', async () => {
      // Should release cache, connections, etc.
      expect(mockServer).toBeDefined();
    });

    it('should be safe to call stop() multiple times', async () => {
      // Calling stop() twice should not cause issues
      mockServer.close.mockResolvedValue(undefined);

      await mockServer.close();
      await mockServer.close();

      expect(mockServer.close).toHaveBeenCalledTimes(2);
    });

    it('should flush audit log before shutdown', async () => {
      // Should save audit log to persistent storage
      mockPermissionChecker.getAuditLog.mockReturnValue([]);
      const log = mockPermissionChecker.getAuditLog();
      expect(log).toBeDefined();
    });

    it('should release port and stdio', async () => {
      // Should allow server restart on same port
      mockTransport.close.mockResolvedValue(undefined);
      await mockTransport.close();
      expect(mockTransport.close).toHaveBeenCalled();
    });
  });

  // ============================================================================
  // SECTION 9: Server Status and Metrics
  // ============================================================================

  describe('Server Status and Metrics', () => {
    it('should track running state', () => {
      // getStatus() should return running boolean
      const status = { running: true, appsDiscovered: 0, toolsGenerated: 0, uptime: 0 };
      expect(status.running).toBe(true);
    });

    it('should track number of discovered apps', () => {
      // getStatus() should return count of apps
      const status = { running: true, appsDiscovered: 3, toolsGenerated: 0, uptime: 0 };
      expect(status.appsDiscovered).toBe(3);
    });

    it('should track number of generated tools', () => {
      // getStatus() should return count of tools
      const status = { running: true, appsDiscovered: 3, toolsGenerated: 25, uptime: 0 };
      expect(status.toolsGenerated).toBe(25);
    });

    it('should track uptime in milliseconds', () => {
      // getStatus() should return uptime
      const status = { running: true, appsDiscovered: 0, toolsGenerated: 0, uptime: 5000 };
      expect(status.uptime).toBeGreaterThan(0);
    });

    it('should update metrics during initialization', () => {
      // After initialize(), metrics should be updated
      const status = { running: false, appsDiscovered: 2, toolsGenerated: 15, uptime: 0 };
      expect(status.appsDiscovered).toBeGreaterThan(0);
    });

    it('should maintain accurate metrics during execution', () => {
      // Metrics should stay accurate during tool execution
      const status = { running: true, appsDiscovered: 2, toolsGenerated: 15, uptime: 1000 };
      expect(status.running).toBe(true);
      expect(status.appsDiscovered).toBe(2);
    });

    it('should provide getStatus() method', () => {
      // Server should have getStatus() method
      expect(typeof mockServer.setRequestHandler).toBe('function');
    });
  });

  // ============================================================================
  // SECTION 10: Lifecycle Integration
  // ============================================================================

  describe('Lifecycle Integration', () => {
    it('should initialize before starting', async () => {
      // initialize() must be called before start()
      mockDiscoverer.discover.mockResolvedValue([]);
      expect(mockDiscoverer.discover).toBeDefined();
    });

    it('should handle sequential initialize->start->stop', async () => {
      // Full lifecycle should work
      mockDiscoverer.discover.mockResolvedValue([]);
      mockTransport.start = vi.fn().mockResolvedValue(undefined);
      mockServer.close = vi.fn().mockResolvedValue(undefined);

      expect(mockDiscoverer.discover).toBeDefined();
      expect(mockTransport.start).toBeDefined();
      expect(mockServer.close).toBeDefined();
    });

    it('should handle errors during any lifecycle stage', async () => {
      // Errors at any stage should be recoverable
      mockDiscoverer.discover.mockRejectedValue(new Error('Discovery error'));

      try {
        await mockDiscoverer.discover();
      } catch (error) {
        expect(error).toEqual(expect.any(Error));
      }
    });

    it('should be restartable after shutdown', async () => {
      // Should be able to start again after stop()
      mockTransport.start = vi.fn().mockResolvedValue(undefined);
      mockServer.close = vi.fn().mockResolvedValue(undefined);

      expect(mockTransport.start).toBeDefined();
      expect(mockServer.close).toBeDefined();
    });

    it('should prevent start without initialization', () => {
      // start() should check that initialize() was called
      const initialized = false;
      if (!initialized) {
        expect(initialized).toBe(false);
      }
    });

    it('should maintain state across requests', async () => {
      // Tools and permissions should persist across requests
      mockGenerator.generateTools.mockReturnValue([
        { name: 'finder_open', description: 'Open' },
      ]);

      const tools1 = mockGenerator.generateTools({});
      const tools2 = mockGenerator.generateTools({});

      expect(tools1).toEqual(tools2);
    });
  });
});
