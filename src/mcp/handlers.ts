/**
 * MCP Request Handlers
 *
 * Implements the MCP protocol handlers that expose the JITD execution layer as MCP tools.
 *
 * Handlers:
 * - ListTools: Discover and list all available MCP tools from macOS applications
 * - CallTool: Execute an MCP tool with permission checks and error handling
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
} from '@modelcontextprotocol/sdk/types.js';
import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import type { PermissionDecision } from '../permissions/types.js';
import type { ToolGenerator } from '../jitd/tool-generator/generator.js';
import type { MacOSAdapter } from '../adapters/macos/macos-adapter.js';
import type { PermissionChecker } from '../permissions/permission-checker.js';
import type { ErrorHandler } from '../error-handler.js';
import type { MCPTool } from '../types/mcp-tool.js';
import { findAllScriptableApps, type AppWithSDEF } from '../jitd/discovery/find-sdef.js';
import { sdefParser } from '../jitd/discovery/parse-sdef.js';
import { buildMetadata } from '../jitd/discovery/app-metadata-builder.js';
import { loadAppTools } from '../jitd/discovery/app-tools-loader.js';
import type { AppMetadata } from '../types/app-metadata.js';
import type { PerAppCache } from '../jitd/cache/per-app-cache.js';

/**
 * Maximum length for app_name parameter to prevent DoS attacks
 */
const MAX_APP_NAME_LENGTH = 100;

/**
 * Setup MCP request handlers
 *
 * Registers all MCP protocol handlers with the server:
 * - ListTools: Returns all discovered tools
 * - CallTool: Executes a tool with permission checks
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
  errorHandler: ErrorHandler,
  perAppCache: PerAppCache
): Promise<void> {
  // Store discovered tools in memory for CallTool lookups
  let discoveredTools: MCPTool[] = [];

  // Store discovered apps for lazy loading
  let discoveredApps: AppWithSDEF[] = [];

  /**
   * ListTools Handler (Lazy Loading)
   *
   * Called by MCP clients to discover available tools.
   * Returns only the get_app_tools tool plus app metadata for lazy loading.
   * This allows fast initialization (<1s) instead of generating all tools upfront.
   */
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    try {
      console.error('[ListTools] Starting lazy loading app discovery');

      // Discover all scriptable apps (just find SDEF files, don't parse yet)
      const apps = await findAllScriptableApps({ useCache: false });
      console.error(`[ListTools] Discovered ${apps.length} scriptable apps`);

      // Store for lazy loading in CallTool handler
      discoveredApps = apps;

      if (apps.length === 0) {
        console.error('[ListTools] No scriptable apps found');
        return {
          tools: [],
          _app_metadata: [],
        };
      }

      // Build metadata for each app IN PARALLEL (critical for <1s performance)
      const metadataPromises = apps.map(async (app) => {
        try {
          console.error(`[ListTools] Building metadata for ${app.appName}`);

          // Parse SDEF dictionary (fast - just XML parsing)
          const dictionary = await sdefParser.parse(app.sdefPath);

          // Build lightweight metadata (20-30ms per app, but parallelized)
          return await buildMetadata(app, dictionary);
        } catch (error) {
          // Log error but don't fail entire ListTools call
          const errorMsg = error instanceof Error ? error.message : String(error);
          console.error(`[ListTools] Failed to build metadata for ${app.appName}: ${errorMsg}`);
          return null;
        }
      });

      // Wait for all metadata to be built in parallel
      const metadataResults = await Promise.all(metadataPromises);

      // Filter out null results (apps that failed to parse)
      const appMetadataList = metadataResults.filter(
        (metadata): metadata is AppMetadata => metadata !== null
      );

      console.error(`[ListTools] Built metadata for ${appMetadataList.length} apps`);

      // Create the get_app_tools tool
      const getAppToolsTool: Tool = {
        name: 'get_app_tools',
        description: 'Get all available tools and object model for a specific macOS application. Use this to load tools on-demand for any discovered app.',
        inputSchema: {
          type: 'object',
          properties: {
            app_name: {
              type: 'string',
              description: 'Application name (e.g., \'Finder\', \'Safari\') from the app metadata list',
            },
          },
          required: ['app_name'],
        },
      };

      // Create the list_apps tool
      const listAppsTool: Tool = {
        name: 'list_apps',
        description: 'List all available macOS applications with their metadata',
        inputSchema: {
          type: 'object',
          properties: {},
          required: [],
        },
      };

      // Return get_app_tools tool + list_apps tool + app metadata
      return {
        tools: [getAppToolsTool, listAppsTool],
        _app_metadata: appMetadataList,
      };

    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(`[ListTools] Error: ${message}`);
      return {
        tools: [],
        _error: message,
      };
    }
  });

  /**
   * CallTool Handler (Lazy Loading)
   *
   * Called by MCP clients to execute a tool.
   * Handles both:
   * - get_app_tools: Lazy load tools for a specific app
   * - App-specific commands: Execute tool with permission checks
   */
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name: toolName, arguments: args } = request.params;

    try {
      console.error(`[CallTool] Executing tool: ${toolName}`);

      // Check for list_apps (return all apps with metadata)
      if (toolName === 'list_apps') {
        try {
          console.error('[CallTool] Handling list_apps request');

          // Reuse the app discovery and metadata building from ListTools
          const apps = await findAllScriptableApps({ useCache: false });
          console.error(`[CallTool/list_apps] Discovered ${apps.length} scriptable apps`);

          if (apps.length === 0) {
            return {
              content: [{
                type: 'text' as const,
                text: JSON.stringify({
                  totalApps: 0,
                  apps: [],
                }),
              }],
            };
          }

          // Build metadata for each app in parallel
          const metadataPromises = apps.map(async (app) => {
            try {
              console.error(`[CallTool/list_apps] Building metadata for ${app.appName}`);

              // Parse SDEF dictionary
              const dictionary = await sdefParser.parse(app.sdefPath);

              // Build metadata
              return await buildMetadata(app, dictionary);
            } catch (error) {
              // Log error but don't fail entire list_apps call
              const errorMsg = error instanceof Error ? error.message : String(error);
              console.error(`[CallTool/list_apps] Failed to build metadata for ${app.appName}: ${errorMsg}`);
              return null;
            }
          });

          // Wait for all metadata to be built in parallel
          const metadataResults = await Promise.all(metadataPromises);

          // Filter out null results (apps that failed to parse)
          const appMetadataList = metadataResults.filter(
            (metadata): metadata is AppMetadata => metadata !== null
          );

          // Sort apps alphabetically by name for consistent ordering
          appMetadataList.sort((a, b) => a.appName.localeCompare(b.appName));

          console.error(`[CallTool/list_apps] Built metadata for ${appMetadataList.length} apps`);

          // Build response in the expected format
          const response = {
            totalApps: appMetadataList.length,
            apps: appMetadataList.map(metadata => ({
              name: metadata.appName,
              bundleId: metadata.bundleId,
              description: metadata.description,
              toolCount: metadata.toolCount,
              suites: metadata.suiteNames,
            })),
          };

          return {
            content: [{
              type: 'text' as const,
              text: JSON.stringify(response),
            }],
          };
        } catch (error) {
          // Handle errors
          const message = error instanceof Error ? error.message : String(error);
          console.error(`[CallTool/list_apps] Error: ${message}`);
          return {
            content: [{
              type: 'text' as const,
              text: `Error listing apps: ${message}`,
            }],
            isError: true,
          };
        }
      }

      // Check for get_app_tools (lazy loading)
      if (toolName === 'get_app_tools') {
        // Validate app_name parameter
        const appName = args?.app_name as string | undefined;

        if (!appName) {
          return {
            content: [{
              type: 'text' as const,
              text: 'Error: Missing required parameter \'app_name\'',
            }],
            isError: true,
          };
        }

        // Input validation for app_name (security: prevent command injection)
        // 1. Length limit (prevent buffer overflow/DoS)
        if (appName.length > MAX_APP_NAME_LENGTH) {
          return {
            content: [{
              type: 'text' as const,
              text: `Error: app_name parameter too long (max ${MAX_APP_NAME_LENGTH} characters)`,
            }],
            isError: true,
          };
        }

        // 2. Character whitelist (alphanumeric + common app name characters)
        if (!/^[a-zA-Z0-9\s\-_.]+$/.test(appName)) {
          return {
            content: [{
              type: 'text' as const,
              text: 'Error: app_name contains invalid characters. Only alphanumeric, spaces, hyphens, underscores, and periods allowed.',
            }],
            isError: true,
          };
        }

        // 3. Null byte rejection (prevent null byte injection)
        if (appName.includes('\0')) {
          return {
            content: [{
              type: 'text' as const,
              text: 'Error: app_name contains null bytes',
            }],
            isError: true,
          };
        }

        try {
          // Load tools for this app (uses cache if available)
          const appToolsResponse = await loadAppTools(
            appName,
            discoveredApps,
            sdefParser,
            toolGenerator,
            perAppCache
          );

          // Return tools + object model as JSON
          return {
            content: [{
              type: 'text' as const,
              text: JSON.stringify(appToolsResponse, null, 2),
            }],
          };
        } catch (error) {
          // Handle specific error types
          if (error && typeof error === 'object' && 'name' in error) {
            if (error.name === 'AppNotFoundError') {
              return {
                content: [{
                  type: 'text' as const,
                  text: `Error: Application "${appName}" not found. Use list_tools to see available apps.`,
                }],
                isError: true,
              };
            }
          }

          // Other errors
          const message = error instanceof Error ? error.message : String(error);
          return {
            content: [{
              type: 'text' as const,
              text: `Error loading tools for ${appName}: ${message}`,
            }],
            isError: true,
          };
        }
      }

      // Continue with existing tool lookup logic for app-specific commands
      // 1. Lookup tool by name
      const tool = discoveredTools.find(t => t.name === toolName);

      if (!tool) {
        console.error(`[CallTool] Tool not found: ${toolName}`);
        const errorResponse = formatErrorResponse('Tool not found', {
          toolName,
          availableTools: discoveredTools.map(t => t.name).slice(0, 10), // Show first 10
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

      // 2. Validate arguments against inputSchema
      const validationResult = validateToolArguments(args || {}, tool.inputSchema);

      if (!validationResult.valid) {
        console.error(`[CallTool] Invalid arguments: ${validationResult.errors.join(', ')}`);
        const errorResponse = formatErrorResponse('Invalid arguments', {
          toolName,
          errors: validationResult.errors,
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

      // 3. Check permissions (skip if DISABLE_PERMISSIONS is set)
      const permissionsDisabled = process.env.DISABLE_PERMISSIONS === 'true';
      if (!permissionsDisabled) {
        const permissionDecision = await permissionChecker.check(tool, args || {});

        if (!permissionDecision.allowed) {
          console.error(`[CallTool] Permission denied: ${permissionDecision.reason}`);
          const errorResponse = formatPermissionDeniedResponse(permissionDecision);

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

        console.error(`[CallTool] Permission granted, executing via adapter`);
      } else {
        console.error(`[CallTool] Permissions disabled (DISABLE_PERMISSIONS=true), executing via adapter`);
      }

      // 4. Execute via MacOSAdapter
      const executionResult = await adapter.execute(tool, args || {});

      // 5. Format and return result
      if (executionResult.success) {
        console.error(`[CallTool] Execution successful`);
        const successResponse = formatSuccessResponse(executionResult.data);

        return {
          content: [
            {
              type: 'text' as const,
              text: JSON.stringify(successResponse),
            },
          ],
        };
      } else {
        console.error(`[CallTool] Execution failed: ${executionResult.error?.message}`);

        // Use ErrorHandler to format execution error
        const handledError = errorHandler.handle(
          {
            type: executionResult.error?.type || 'EXECUTION_ERROR',
            message: executionResult.error?.message || 'Unknown error',
            originalError: executionResult.error?.message,
          },
          {
            appName: tool._metadata?.appName || 'Unknown',
            commandName: tool._metadata?.commandName || toolName,
            parameters: args || {},
          }
        );

        const errorResponse = {
          error: handledError.message,
          suggestion: handledError.suggestion,
          code: handledError.type,
          retryable: handledError.retryable,
          originalError: handledError.originalError,
        };

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

    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(`[CallTool] Unexpected error: ${message}`);
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

