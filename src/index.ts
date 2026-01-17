#!/usr/bin/env node

/**
 * iac-mcp - Universal bridge between AI/LLMs and native macOS applications
 *
 * Entry point for the MCP server implementing Just-In-Time Discovery (JITD)
 * to dynamically discover and orchestrate any installed scriptable app.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

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

  const server = new Server(
    {
      name: 'iac-mcp',
      version: '0.1.0',
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  // List tools handler - will dynamically generate from discovered apps
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    log('INFO', 'ListTools request received');
    // TODO: Implement JITD discovery and tool generation
    const tools = [
      {
        name: 'example_tool',
        description: 'Example tool - replace with JITD-generated tools',
        inputSchema: {
          type: 'object',
          properties: {
            message: {
              type: 'string',
              description: 'Message to echo',
            },
          },
          required: ['message'],
        },
      },
    ];
    log('INFO', `Returning ${tools.length} tool(s)`);
    return { tools };
  });

  // Call tool handler - route to execution layer
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    log('INFO', `CallTool request: ${name}`, args);

    // TODO: Implement tool execution with permissions
    if (name === 'example_tool') {
      const result = `Echo: ${(args as { message: string }).message}`;
      log('INFO', `Tool execution successful: ${name}`);
      return {
        content: [
          {
            type: 'text',
            text: result,
          },
        ],
      };
    }

    log('ERROR', `Unknown tool requested: ${name}`);
    throw new Error(`Unknown tool: ${name}`);
  });

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
  const transport = new StdioServerTransport();
  await server.connect(transport);

  log('INFO', 'iac-mcp server started successfully');
  log('INFO', 'Listening on stdio transport');
  log('INFO', 'Server ready to accept requests');
}

// Run the server
main().catch((error) => {
  log('ERROR', 'Fatal error during server startup', error);
  process.exit(1);
});
