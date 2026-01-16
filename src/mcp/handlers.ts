/**
 * MCP Request Handlers
 *
 * Implements the MCP protocol handlers that expose the JITD execution layer as MCP tools.
 *
 * Handlers:
 * - ListTools: Discover and list all available MCP tools from macOS applications
 * - CallTool: Execute an MCP tool with permission checks and error handling
 * - ListResources: List available resources (app dictionaries)
 * - ReadResource: Retrieve a specific resource by URI
 *
 * Integration points:
 * - ToolGenerator: Generates MCP tool definitions from SDEF data
 * - MacOSAdapter: Executes tools via JXA on macOS
 * - PermissionChecker: Enforces permission policies before execution
 * - ErrorHandler: Formats execution errors for MCP protocol
 *
 * Reference: planning/WEEK-3-EXECUTION-LAYER.md (lines 602-712)
 */

import type { Server } from '@modelcontextprotocol/sdk/server/index.js';
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
  TextContent,
} from '@modelcontextprotocol/sdk/types.js';
import type { Tool } from '@modelcontextprotocol/sdk/types.js';

import type { MCPTool } from '../types/mcp-tool.js';
import type { PermissionDecision } from '../permissions/types.js';
import type { ToolGenerator } from '../jitd/tool-generator/generator.js';
import type { MacOSAdapter } from '../adapters/macos/macos-adapter.js';
import type { PermissionChecker } from '../permissions/permission-checker.js';
import type { ErrorHandler } from '../error-handler.js';

/**
 * Resource cache for app dictionaries
 * Maps URI → resource content
 */
type ResourceCache = Map<string, { uri: string; name: string; content: string }>;

/**
 * Setup MCP request handlers
 *
 * Registers all MCP protocol handlers with the server:
 * - ListTools: Returns all discovered tools
 * - CallTool: Executes a tool with permission checks
 * - ListResources: Lists available app dictionaries
 * - ReadResource: Retrieves a specific app dictionary
 *
 * @param server - MCP Server instance
 * @param toolGenerator - ToolGenerator instance for discovering tools
 * @param permissionChecker - PermissionChecker for permission enforcement
 * @param adapter - MacOSAdapter for tool execution
 * @param errorHandler - ErrorHandler for error formatting
 *
 * @example
 * ```typescript
 * const server = new Server({ name: 'iac-bridge', version: '1.0.0' });
 * setupHandlers(server, jitd, permissionChecker, adapter, errorHandler);
 * await server.connect(transport);
 * ```
 */
export async function setupHandlers(
  server: Server,
  toolGenerator: ToolGenerator,
  permissionChecker: PermissionChecker,
  adapter: MacOSAdapter,
  errorHandler: ErrorHandler
): Promise<void> {
  // Initialize resource cache for app dictionaries
  const resourceCache: ResourceCache = new Map();

  /**
   * ListTools Handler
   *
   * Called by MCP clients to discover available tools.
   * Generates tools from JITD engine and returns them in MCP format.
   */
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    try {
      // In a real implementation, we would:
      // 1. Call toolGenerator.generateTools() for discovered apps
      // 2. Format them as MCP Tool objects
      // 3. Return in MCP response format

      // For now, return empty tools array
      // The actual tool discovery happens via ToolGenerator
      const tools: Tool[] = [];

      return { tools };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        tools: [],
        _error: message,
      };
    }
  });

  /**
   * CallTool Handler
   *
   * Called by MCP clients to execute a tool.
   * Performs:
   * 1. Tool lookup by name
   * 2. Parameter validation
   * 3. Permission check
   * 4. Execution via MacOSAdapter
   * 5. Error handling and formatting
   */
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name: toolName, arguments: args } = request.params;

    try {
      // In a real implementation, we would:
      // 1. Lookup tool by name from generated tools
      // 2. Validate arguments against inputSchema
      // 3. Check permissions via permissionChecker.check()
      // 4. If permission denied, return permission denied error
      // 5. If permission allowed, execute via adapter.execute()
      // 6. Return result formatted as MCP TextContent

      // Placeholder: return tool not found error
      const errorResponse = formatErrorResponse('Tool not found', {
        toolName,
      });

      return {
        content: [
          {
            type: 'text' as const,
            text: JSON.stringify(errorResponse),
          },
        ],
        isError: true,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      const errorResponse = formatErrorResponse(message, {
        toolName,
      });

      return {
        content: [
          {
            type: 'text' as const,
            text: JSON.stringify(errorResponse),
          },
        ],
        isError: true,
      };
    }
  });

  /**
   * ListResources Handler (Optional)
   *
   * Called by MCP clients to discover available resources.
   * Returns app dictionary resources for each discovered app.
   */
  server.setRequestHandler(ListResourcesRequestSchema, async () => {
    try {
      // In a real implementation:
      // 1. For each discovered app, create a resource URI
      // 2. Format: iac://apps/{bundleId}/dictionary
      // 3. Return list of resources

      return {
        resources: [],
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        resources: [],
        _error: message,
      };
    }
  });

  /**
   * ReadResource Handler (Optional)
   *
   * Called by MCP clients to retrieve a specific resource.
   * Returns parsed SDEF dictionary for an app.
   */
  server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
    const { uri } = request.params;

    try {
      // Check cache first
      const cached = resourceCache.get(uri);
      if (cached) {
        return {
          contents: [
            {
              uri: cached.uri,
              mimeType: 'application/json',
              text: cached.content,
            },
          ],
        };
      }

      // In a real implementation:
      // 1. Parse URI to extract bundleId
      // 2. Look up app in discovered apps
      // 3. Get parsed SDEF data
      // 4. Format as LLM-friendly dictionary
      // 5. Cache result
      // 6. Return as MCP resource

      return {
        contents: [
          {
            uri,
            mimeType: 'application/json',
            text: JSON.stringify({
              error: 'Resource not found',
              uri,
            }),
          },
        ],
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        contents: [
          {
            uri,
            mimeType: 'application/json',
            text: JSON.stringify({
              error: message,
              uri,
            }),
          },
        ],
      };
    }
  });
}

/**
 * Format an error response for MCP protocol
 *
 * Creates a structured error response that includes:
 * - User-friendly error message
 * - Error code for debugging
 * - Additional context
 *
 * @param message - Error message
 * @param context - Additional error context
 * @returns Formatted error object
 */
function formatErrorResponse(
  message: string,
  context: Record<string, any> = {}
): Record<string, any> {
  return {
    error: message,
    code: getErrorCode(message),
    timestamp: new Date().toISOString(),
    ...context,
  };
}

/**
 * Determine error code from error message
 *
 * Maps error messages to standardized error codes for debugging.
 *
 * @param message - Error message
 * @returns Error code
 */
function getErrorCode(message: string): string {
  if (message.includes('not found')) return 'NOT_FOUND';
  if (message.includes('Permission')) return 'PERMISSION_DENIED';
  if (message.includes('timeout')) return 'TIMEOUT';
  if (message.includes('Invalid')) return 'INVALID_ARGUMENT';
  if (message.includes('AppleScript')) return 'APPLESCRIPT_ERROR';
  return 'EXECUTION_ERROR';
}

/**
 * Validate tool arguments against schema
 *
 * Checks that provided arguments match the tool's input schema.
 *
 * @param args - Provided arguments
 * @param schema - Tool input schema
 * @returns Validation result with any errors
 */
export function validateToolArguments(
  args: Record<string, any>,
  schema: any
): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  // Check required fields
  if (schema.required) {
    for (const required of schema.required) {
      if (!(required in args)) {
        errors.push(`Missing required argument: ${required}`);
      }
    }
  }

  // Check argument types
  if (schema.properties) {
    for (const [key, value] of Object.entries(args)) {
      const propertySchema = schema.properties[key] as any;
      if (propertySchema && propertySchema.type) {
        const actualType = typeof value;
        const expectedType = propertySchema.type;

        // Type checking (simplified)
        if (expectedType === 'string' && actualType !== 'string') {
          errors.push(`Argument "${key}" must be a string`);
        } else if (expectedType === 'number' && actualType !== 'number') {
          errors.push(`Argument "${key}" must be a number`);
        } else if (expectedType === 'boolean' && actualType !== 'boolean') {
          errors.push(`Argument "${key}" must be a boolean`);
        } else if (expectedType === 'array' && !Array.isArray(value)) {
          errors.push(`Argument "${key}" must be an array`);
        } else if (expectedType === 'object' && typeof value !== 'object') {
          errors.push(`Argument "${key}" must be an object`);
        }
      }
    }
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Format a successful tool execution result
 *
 * Creates an MCP-compliant response for a successful tool execution.
 *
 * @param result - Execution result data
 * @param metadata - Optional execution metadata
 * @returns MCP response object
 */
export function formatSuccessResponse(
  result: any,
  metadata?: Record<string, any>
): Record<string, any> {
  const response: any = {
    success: true,
    data: result,
  };

  if (metadata) {
    response.metadata = metadata;
  }

  return response;
}

/**
 * Format a permission denied response
 *
 * Creates an MCP error response for a permission denial.
 *
 * @param decision - Permission decision with reason
 * @returns MCP error response object
 */
export function formatPermissionDeniedResponse(decision: PermissionDecision): Record<string, any> {
  return {
    error: 'Permission denied',
    reason: decision.reason,
    level: decision.level,
    requiresPrompt: decision.requiresPrompt,
    timestamp: new Date().toISOString(),
  };
}

// Export types for usage in other modules
export type { ResourceCache };
