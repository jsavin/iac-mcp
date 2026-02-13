#!/usr/bin/env node

/**
 * iac-mcp - Universal bridge between AI/LLMs and native macOS applications
 *
 * Entry point for the MCP server implementing Just-In-Time Discovery (JITD)
 * to dynamically discover and orchestrate any installed scriptable app.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { setupHandlers } from './mcp/handlers.js';
import { ToolGenerator } from './jitd/tool-generator/generator.js';
import { MacOSAdapter } from './adapters/macos/macos-adapter.js';
import { PermissionChecker } from './permissions/permission-checker.js';
import { ErrorHandler } from './error-handler.js';
import { PerAppCache } from './jitd/cache/per-app-cache.js';
import { ReferenceStore } from './execution/reference-store.js';
import { QueryExecutor } from './execution/query-executor.js';
import { JXAExecutor } from './adapters/macos/jxa-executor.js';
import { SystemEventsExecutor } from './execution/system-events-executor.js';

/**
 * Logging utility that writes to stderr (stdout is reserved for MCP protocol)
 */
function log(level: 'INFO' | 'WARN' | 'ERROR', message: string, data?: unknown): void {
  const timestamp = new Date().toISOString();
  const logMessage = data
    ? `[${timestamp}] [${level}] ${message} ${JSON.stringify(data)}`
    : `[${timestamp}] [${level}] ${message}`;
  console.error(logMessage);
}

/**
 * Initialize the MCP server
 */
async function main(): Promise<void> {
  log('INFO', 'Starting iac-mcp server...');
  log('INFO', 'Server version: 0.1.0');
  log('INFO', 'Node version: ' + process.version);
  log('INFO', 'Platform: ' + process.platform);

  // Create server instance
  const server = new Server(
    {
      name: 'iac-mcp',
      version: '0.1.0',
    },
    {
      capabilities: {
        tools: {},
        resources: {},
      },
    }
  );

  // Initialize JITD components
  const toolGenerator = new ToolGenerator();
  const adapter = new MacOSAdapter();
  const permissionChecker = new PermissionChecker();
  const errorHandler = new ErrorHandler();
  const perAppCache = new PerAppCache();

  // Initialize query execution components
  const referenceStore = new ReferenceStore(15 * 60 * 1000); // 15-minute TTL
  const jxaExecutor = new JXAExecutor();
  const queryExecutor = new QueryExecutor(referenceStore, jxaExecutor);
  const systemEventsExecutor = new SystemEventsExecutor(referenceStore, jxaExecutor);

  // Setup all MCP handlers
  try {
    await setupHandlers(
      server,
      toolGenerator,
      permissionChecker,
      adapter,
      errorHandler,
      perAppCache,
      queryExecutor,
      systemEventsExecutor
    );
    log('INFO', 'MCP handlers setup complete');
  } catch (error) {
    log('ERROR', 'Failed to setup MCP handlers', error);
    throw error;
  }

  // Graceful shutdown handlers
  const shutdown = async (signal: string): Promise<void> => {
    log('INFO', `Received ${signal}, shutting down gracefully...`);
    try {
      await server.close();
      log('INFO', 'Server closed successfully');
      process.exit(0);
    } catch (error) {
      log('ERROR', 'Error during shutdown', error);
      process.exit(1);
    }
  };

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));

  // Start the server with stdio transport
  try {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    log('INFO', 'iac-mcp server started successfully');
    log('INFO', 'Listening on stdio transport');
    log('INFO', 'Server ready to accept requests');
  } catch (error) {
    log('ERROR', 'Failed to connect to stdio transport', error);
    throw error;
  }
}

// Run the server
main().catch((error) => {
  log('ERROR', 'Fatal error during server startup', error);
  process.exit(1);
});
