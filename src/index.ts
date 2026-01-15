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
 * Initialize the MCP server
 */
async function main(): Promise<void> {
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
    // TODO: Implement JITD discovery and tool generation
    return {
      tools: [
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
      ],
    };
  });

  // Call tool handler - route to execution layer
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    // TODO: Implement tool execution with permissions
    if (name === 'example_tool') {
      return {
        content: [
          {
            type: 'text',
            text: `Echo: ${(args as { message: string }).message}`,
          },
        ],
      };
    }

    throw new Error(`Unknown tool: ${name}`);
  });

  // Start the server with stdio transport
  const transport = new StdioServerTransport();
  await server.connect(transport);

  console.error('iac-mcp server started successfully');
}

// Run the server
main().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});
