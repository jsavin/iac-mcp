/**
 * IACMCPServer - Main MCP Server Implementation
 *
 * Integrates all components (JITD, handlers, permissions) via MCP protocol.
 *
 * Responsibilities:
 * 1. Initialize and coordinate all components
 * 2. Perform app discovery via JITD engine
 * 3. Parse SDEF files and generate MCP tools
 * 4. Setup MCP request handlers (ListTools, CallTool)
 * 5. Connect to stdio transport for MCP communication
 * 6. Track metrics and server status
 * 7. Handle graceful shutdown
 *
 * Reference: planning/WEEK-3-EXECUTION-LAYER.md (lines 502-560)
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
  TextContent,
  Tool,
} from '@modelcontextprotocol/sdk/types.js';

import { findAllScriptableApps, SDEFParser } from '../jitd/discovery/index.js';
import { ToolGenerator } from '../jitd/tool-generator/generator.js';
import { MacOSAdapter } from '../adapters/macos/macos-adapter.js';
import { PermissionChecker } from '../permissions/permission-checker.js';
import { ErrorHandler } from '../error-handler.js';
import { ToolCache } from '../jitd/cache/tool-cache.js';
import { setupHandlers, validateToolArguments } from './handlers.js';
import type { MCPTool } from '../types/mcp-tool.js';

/**
 * Server configuration options
 */
export interface ServerOptions {
  /**
   * Application discovery paths
   * Default: ['/Applications', '/System/Library/CoreServices']
   */
  discoveryPaths?: string[];

  /**
   * Enable caching of parsed SDEF files
   * Default: true
   */
  enableCache?: boolean;

  /**
   * Cache directory for storing parsed SDEF data
   * Default: system temp directory
   */
  cacheDir?: string;

  /**
   * Timeout for tool execution in milliseconds
   * Default: 30000 (30 seconds)
   */
  timeoutMs?: number;

  /**
   * Custom server name
   * Default: 'iac-mcp'
   */
  serverName?: string;

  /**
   * Enable verbose logging
   * Default: false
   */
  enableLogging?: boolean;
}

/**
 * Server status and metrics
 */
export interface ServerStatus {
  running: boolean;
  initialized: boolean;
  appsDiscovered: number;
  toolsGenerated: number;
  uptime: number; // milliseconds
  startTime?: Date;
}

/**
 * IACMCPServer
 *
 * Main MCP server implementation that integrates all IAC-MCP components.
 * Manages the complete lifecycle from initialization through execution.
 */
export class IACMCPServer {
  private server: Server;
  private transport?: StdioServerTransport;
  private options: Required<ServerOptions>;
  private discoverer = findAllScriptableApps;
  private parser = new SDEFParser();
  private generator: ToolGenerator;
  private adapter: MacOSAdapter;
  private permissionChecker: PermissionChecker;
  private errorHandler: ErrorHandler;
  private toolCache: ToolCache;

  // State tracking
  private status: ServerStatus = {
    running: false,
    initialized: false,
    appsDiscovered: 0,
    toolsGenerated: 0,
    uptime: 0,
  };

  private discoveredApps: Array<{
    appName: string;
    bundlePath: string;
    sdefPath: string;
  }> = [];
  private generatedTools: MCPTool[] = [];
  private startTime: number = 0;

  /**
   * Create a new IACMCPServer
   *
   * @param options - Server configuration options
   */
  constructor(options?: ServerOptions) {
    // Initialize options with defaults
    this.options = {
      discoveryPaths: options?.discoveryPaths ?? ['/Applications', '/System/Library/CoreServices'],
      enableCache: options?.enableCache ?? true,
      cacheDir: options?.cacheDir ?? '/tmp/iac-cache',
      timeoutMs: options?.timeoutMs ?? 30000,
      serverName: options?.serverName ?? 'iac-mcp',
      enableLogging: options?.enableLogging ?? false,
    };

    // Initialize MCP server
    this.server = new Server(
      {
        name: this.options.serverName,
        version: '0.1.0',
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    // Initialize components
    this.generator = new ToolGenerator({
      strictValidation: true,
      namingStrategy: 'app_prefix',
    });

    this.adapter = new MacOSAdapter({
      timeoutMs: this.options.timeoutMs,
      enableLogging: this.options.enableLogging,
    });

    this.permissionChecker = new PermissionChecker();
    this.errorHandler = new ErrorHandler();
    this.toolCache = new ToolCache(this.options.cacheDir);
  }

  /**
   * Initialize the server
   *
   * Performs:
   * 1. Discover installed applications with SDEF files
   * 2. Parse SDEF files for each app
   * 3. Generate MCP tools from parsed SDEF data
   * 4. Setup MCP request handlers
   * 5. Update metrics
   *
   * @throws Error if discovery or parsing fails fatally
   */
  async initialize(): Promise<void> {
    try {
      if (this.options.enableLogging) {
        console.error('[IACMCPServer] Starting initialization...');
      }

      // Discover applications with SDEF files
      // Note: findAllScriptableApps searches predefined directories
      // The discoveryPaths option is kept for future extensibility
      this.discoveredApps = await this.discoverer({
        useCache: this.options.enableCache,
      });
      this.status.appsDiscovered = this.discoveredApps.length;

      if (this.options.enableLogging) {
        console.error(`[IACMCPServer] Discovered ${this.discoveredApps.length} apps with SDEF files`);
      }

      // Parse SDEF files and generate tools for each app
      for (const app of this.discoveredApps) {
        try {
          // Parse SDEF file
          const dictionary = await this.parser.parse(app.sdefPath);

          // Generate tools from parsed SDEF
          const tools = this.generator.generateTools(dictionary, {
            appName: app.appName,
            bundleId: this.extractBundleId(app.bundlePath),
            bundlePath: app.bundlePath,
            sdefPath: app.sdefPath,
          });

          this.generatedTools.push(...tools);
        } catch (error) {
          // Log app parse error but continue with others
          if (this.options.enableLogging) {
            console.error(`[IACMCPServer] Failed to parse ${app.appName}:`, error);
          }
        }
      }

      this.status.toolsGenerated = this.generatedTools.length;

      if (this.options.enableLogging) {
        console.error(
          `[IACMCPServer] Generated ${this.generatedTools.length} tools from ${this.discoveredApps.length} apps`
        );
      }

      // Setup MCP request handlers
      await setupHandlers(
        this.server,
        this.generator,
        this.permissionChecker,
        this.adapter,
        this.errorHandler,
        this.toolCache
      );

      // Override ListTools handler to return generated tools
      await this.server.setRequestHandler(ListToolsRequestSchema, async () => {
        return {
          tools: this.generatedTools.map((tool) => ({
            name: tool.name,
            description: tool.description,
            inputSchema: tool.inputSchema,
          })) as Tool[],
        };
      });

      // Override CallTool handler to execute tools with full pipeline
      await this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
        return this.handleToolCall(request.params.name, request.params.arguments as Record<string, any>);
      });

      this.status.initialized = true;

      if (this.options.enableLogging) {
        console.error('[IACMCPServer] Initialization complete');
      }
    } catch (error) {
      if (this.options.enableLogging) {
        console.error('[IACMCPServer] Initialization failed:', error);
      }
      throw error;
    }
  }

  /**
   * Start the server
   *
   * Performs:
   * 1. Create stdio transport
   * 2. Connect server to transport
   * 3. Mark server as running
   * 4. Log startup success
   *
   * @throws Error if transport fails or connection fails
   */
  async start(): Promise<void> {
    try {
      if (this.status.running) {
        if (this.options.enableLogging) {
          console.error('[IACMCPServer] Server already running, skipping start');
        }
        return;
      }

      if (!this.status.initialized) {
        throw new Error('Server must be initialized before starting');
      }

      // Create and start stdio transport
      this.transport = new StdioServerTransport();
      await this.transport.start();

      // Connect server to transport
      await this.server.connect(this.transport);

      // Mark as running and track start time
      this.status.running = true;
      this.startTime = Date.now();
      this.status.startTime = new Date();

      console.error(
        `[IACMCPServer] Started successfully with ${this.generatedTools.length} tools from ${this.discoveredApps.length} apps`
      );
    } catch (error) {
      if (this.options.enableLogging) {
        console.error('[IACMCPServer] Start failed:', error);
      }
      throw error;
    }
  }

  /**
   * Stop the server
   *
   * Performs:
   * 1. Close stdio transport
   * 2. Close MCP server
   * 3. Mark as not running
   * 4. Release resources
   *
   * Handles multiple calls safely.
   */
  async stop(): Promise<void> {
    try {
      if (!this.status.running) {
        if (this.options.enableLogging) {
          console.error('[IACMCPServer] Server not running, skipping stop');
        }
        return;
      }

      // Close transport
      if (this.transport) {
        await this.transport.close();
        this.transport = undefined;
      }

      // Close server
      await this.server.close();

      // Mark as not running
      this.status.running = false;

      if (this.options.enableLogging) {
        console.error('[IACMCPServer] Stopped successfully');
      }
    } catch (error) {
      if (this.options.enableLogging) {
        console.error('[IACMCPServer] Stop failed:', error);
      }
      throw error;
    }
  }

  /**
   * Get current server status and metrics
   *
   * @returns Current server status
   */
  getStatus(): ServerStatus {
    // Update uptime
    if (this.status.running && this.startTime) {
      this.status.uptime = Date.now() - this.startTime;
    }

    return { ...this.status };
  }

  /**
   * Handle a tool call request
   *
   * Performs full pipeline:
   * 1. Lookup tool by name
   * 2. Validate arguments against schema
   * 3. Check permissions
   * 4. Execute via adapter
   * 5. Return result or error
   *
   * @param toolName - Name of tool to execute
   * @param args - Tool arguments
   * @returns MCP response with result or error
   */
  private async handleToolCall(
    toolName: string,
    args: Record<string, any>
  ): Promise<{
    content: TextContent[];
    isError?: boolean;
  }> {
    try {
      // Step 1: Lookup tool
      const tool = this.generatedTools.find((t) => t.name === toolName);
      if (!tool) {
        return {
          content: [
            {
              type: 'text' as const,
              text: JSON.stringify({
                error: `Tool not found: ${toolName}`,
                code: 'NOT_FOUND',
              }),
            },
          ],
          isError: true,
        };
      }

      // Step 2: Validate arguments
      const validation = validateToolArguments(args, tool.inputSchema);
      if (!validation.valid) {
        return {
          content: [
            {
              type: 'text' as const,
              text: JSON.stringify({
                error: 'Invalid arguments',
                code: 'INVALID_ARGUMENT',
                details: validation.errors,
              }),
            },
          ],
          isError: true,
        };
      }

      // Step 3: Check permissions (skip if DISABLE_PERMISSIONS is set)
      const permissionsDisabled = process.env.DISABLE_PERMISSIONS === 'true';
      let permission = permissionsDisabled
        ? { allowed: true, level: 'ALWAYS_SAFE' as const, reason: 'Permissions disabled', requiresPrompt: false }
        : await this.permissionChecker.check(tool, args);

      if (!permissionsDisabled && !permission.allowed) {
        return {
          content: [
            {
              type: 'text' as const,
              text: JSON.stringify({
                error: 'Permission denied',
                code: 'PERMISSION_DENIED',
                reason: permission.reason,
                level: permission.level,
              }),
            },
          ],
          isError: true,
        };
      }

      // Step 4: Execute tool
      const result = await this.adapter.execute(tool, args);

      // Step 5: Record in audit log (skip if permissions disabled)
      if (!permissionsDisabled) {
        await this.permissionChecker.recordDecision({
          allowed: true,
          level: permission.level,
          reason: permission.reason,
          requiresPrompt: false,
        });
      }

      // Return success response
      return {
        content: [
          {
            type: 'text' as const,
            text: JSON.stringify({
              success: true,
              data: result,
            }),
          },
        ],
      };
    } catch (error) {
      // Handle execution errors
      const message = error instanceof Error ? error.message : String(error);
      return {
        content: [
          {
            type: 'text' as const,
            text: JSON.stringify({
              error: 'Execution failed',
              code: 'EXECUTION_ERROR',
              message,
            }),
          },
        ],
        isError: true,
      };
    }
  }

  /**
   * Extract bundle ID from bundle path
   *
   * @param bundlePath - Path to application bundle
   * @returns Extracted bundle ID or 'unknown'
   */
  private extractBundleId(bundlePath: string): string {
    try {
      // Parse bundle path like /Applications/MyApp.app
      const match = bundlePath.match(/([^/]+)\.app$/);
      if (match && match[1]) {
        return `com.local.${match[1].toLowerCase().replace(/\s+/g, '.')}`;
      }
      return 'com.local.unknown';
    } catch {
      return 'com.local.unknown';
    }
  }
}

/**
 * Create and start an IACMCPServer
 *
 * Helper function for quick setup:
 *
 * @example
 * ```typescript
 * const server = await createAndStartServer();
 * ```
 *
 * @param options - Server configuration options
 * @returns Started IACMCPServer instance
 */
export async function createAndStartServer(options?: ServerOptions): Promise<IACMCPServer> {
  const server = new IACMCPServer(options);
  await server.initialize();
  await server.start();
  return server;
}

