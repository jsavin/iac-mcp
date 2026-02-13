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

import { findAllScriptableApps } from '../jitd/discovery/index.js';
import { ToolGenerator } from '../jitd/tool-generator/generator.js';
import { MacOSAdapter } from '../adapters/macos/macos-adapter.js';
import { JXAExecutor } from '../adapters/macos/jxa-executor.js';
import { PermissionChecker } from '../permissions/permission-checker.js';
import { ErrorHandler } from '../error-handler.js';
import { PerAppCache } from '../jitd/cache/per-app-cache.js';
import { ReferenceStore } from '../execution/reference-store.js';
import { QueryExecutor } from '../execution/query-executor.js';
import { SystemEventsExecutor } from '../execution/system-events-executor.js';
import { LargeValueCache } from '../execution/large-value-cache.js';
import { setupHandlers } from './handlers.js';

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

  /**
   * Disable JXA execution for query tools.
   * When true, query tools return empty/mock results (useful for testing).
   * Default: false
   */
  disableJxaExecution?: boolean;
}

/**
 * Server status and metrics
 */
export interface ServerStatus {
  running: boolean;
  initialized: boolean;
  appsDiscovered: number;
  toolsGenerated: number; // 0 for lazy loading (tools generated on-demand)
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
  private generator: ToolGenerator;
  private adapter: MacOSAdapter;
  private jxaExecutor: JXAExecutor;
  private permissionChecker: PermissionChecker;
  private errorHandler: ErrorHandler;
  private perAppCache: PerAppCache;
  private referenceStore: ReferenceStore;
  private queryExecutor: QueryExecutor;
  private systemEventsExecutor: SystemEventsExecutor;

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
      disableJxaExecution: options?.disableJxaExecution ?? false,
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
          resources: {},
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
    this.perAppCache = new PerAppCache(this.options.cacheDir);

    // Initialize JXA executor for query operations (only if JXA execution is enabled)
    this.jxaExecutor = new JXAExecutor();

    // Initialize query execution components
    // Pass JXAExecutor only if JXA execution is enabled (default: enabled)
    this.referenceStore = new ReferenceStore(15 * 60 * 1000); // 15-minute TTL
    const largeValueCache = new LargeValueCache();
    this.queryExecutor = this.options.disableJxaExecution
      ? new QueryExecutor(this.referenceStore, undefined, largeValueCache)
      : new QueryExecutor(this.referenceStore, this.jxaExecutor, largeValueCache);

    // Initialize System Events executor (shares ReferenceStore with query executor)
    this.systemEventsExecutor = this.options.disableJxaExecution
      ? new SystemEventsExecutor(this.referenceStore)
      : new SystemEventsExecutor(this.referenceStore, this.jxaExecutor);
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

      // Setup MCP request handlers (lazy loading approach)
      // Handlers will discover and generate tools on-demand when called
      await setupHandlers(
        this.server,
        this.generator,
        this.permissionChecker,
        this.adapter,
        this.errorHandler,
        this.perAppCache,
        this.queryExecutor,
        this.systemEventsExecutor
      );

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

      // Create stdio transport (Server.connect() will start it automatically)
      this.transport = new StdioServerTransport();

      // Connect server to transport (this automatically starts the transport)
      await this.server.connect(this.transport);

      // Mark as running and track start time
      this.status.running = true;
      this.startTime = Date.now();
      this.status.startTime = new Date();

      console.error(
        `[IACMCPServer] Started successfully with ${this.discoveredApps.length} apps (tools generated on-demand)`
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
   * Handle a request directly (for testing purposes)
   *
   * This method allows tests to call MCP handlers without going through the transport.
   * It simulates what the MCP transport would do when receiving a request.
   *
   * @param request - MCP request object with method and params
   * @returns MCP response
   */
  async handleRequest(request: { method: string; params: Record<string, unknown> }): Promise<Record<string, unknown>> {
    // Get the internal server's request handlers
    // The MCP SDK Server class stores handlers in a private map
    // We need to access them via the server's internal routing

    if (request.method === 'tools/list') {
      // Call the ListTools handler
      const handler = (this.server as unknown as { _requestHandlers: Map<string, (request: unknown) => Promise<unknown>> })._requestHandlers?.get('tools/list');
      if (handler) {
        return handler({ method: request.method, params: request.params }) as Promise<Record<string, unknown>>;
      }
      throw new Error('ListTools handler not found');
    }

    if (request.method === 'tools/call') {
      // Call the CallTool handler
      const handler = (this.server as unknown as { _requestHandlers: Map<string, (request: unknown) => Promise<unknown>> })._requestHandlers?.get('tools/call');
      if (handler) {
        return handler({ method: request.method, params: request.params }) as Promise<Record<string, unknown>>;
      }
      throw new Error('CallTool handler not found');
    }

    if (request.method === 'resources/list') {
      // Call the ListResources handler
      const handler = (this.server as unknown as { _requestHandlers: Map<string, (request: unknown) => Promise<unknown>> })._requestHandlers?.get('resources/list');
      if (handler) {
        return handler({ method: request.method, params: request.params }) as Promise<Record<string, unknown>>;
      }
      throw new Error('ListResources handler not found');
    }

    if (request.method === 'resources/read') {
      // Call the ReadResource handler
      const handler = (this.server as unknown as { _requestHandlers: Map<string, (request: unknown) => Promise<unknown>> })._requestHandlers?.get('resources/read');
      if (handler) {
        return handler({ method: request.method, params: request.params }) as Promise<Record<string, unknown>>;
      }
      throw new Error('ReadResource handler not found');
    }

    throw new Error(`Unknown method: ${request.method}`);
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

