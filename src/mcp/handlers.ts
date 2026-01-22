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
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
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

// Server-side cache for app metadata
let cachedAppMetadata: AppMetadata[] | null = null;
let cacheTimestamp = 0;
const CACHE_TTL_MS = 60000; // 1 minute TTL

/**
 * Discover and build metadata for all scriptable apps
 *
 * Shared by ListTools, list_apps tool, and iac://apps resource.
 * Implements server-side caching with 1-minute TTL for performance.
 *
 * @returns Array of AppMetadata sorted alphabetically by name
 */
async function discoverAppMetadata(): Promise<AppMetadata[]> {
  // Check cache validity
  const now = Date.now();
  if (cachedAppMetadata && (now - cacheTimestamp) < CACHE_TTL_MS) {
    console.error(`[discoverAppMetadata] Returning cached metadata (age: ${now - cacheTimestamp}ms)`);
    return cachedAppMetadata;
  }

  console.error('[discoverAppMetadata] Cache miss or expired, discovering apps');

  const apps = await findAllScriptableApps({ useCache: false });

  if (apps.length === 0) {
    console.error('[discoverAppMetadata] No scriptable apps found');
    cachedAppMetadata = [];
    cacheTimestamp = now;
    return [];
  }

  console.error(`[discoverAppMetadata] Discovered ${apps.length} scriptable apps`);

  // Build metadata in parallel for performance
  const metadataPromises = apps.map(async (app) => {
    try {
      console.error(`[discoverAppMetadata] Building metadata for ${app.appName}`);
      const dictionary = await sdefParser.parse(app.sdefPath);
      return await buildMetadata(app, dictionary);
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : String(error);
      console.error(`[discoverAppMetadata] Failed to build metadata for ${app.appName}: ${errorMsg}`);
      return null;
    }
  });

  const metadataResults = await Promise.all(metadataPromises);

  // Filter out failed apps
  const appMetadataList = metadataResults.filter(
    (metadata): metadata is AppMetadata => metadata !== null
  );

  // Sort alphabetically for consistent ordering
  appMetadataList.sort((a, b) => a.appName.localeCompare(b.appName));

  console.error(`[discoverAppMetadata] Built metadata for ${appMetadataList.length} apps`);

  // Update cache
  cachedAppMetadata = appMetadataList;
  cacheTimestamp = now;

  return appMetadataList;
}

/**
 * Format app metadata for MCP response
 *
 * Shared by list_apps tool and iac://apps resource for consistency.
 * Performs runtime validation and maps AppMetadata to response format.
 *
 * @param appMetadataList - Array of app metadata from discovery
 * @returns Formatted response with totalApps count and apps array
 */
function formatAppMetadataResponse(appMetadataList: AppMetadata[]) {
  return {
    totalApps: appMetadataList.length,
    apps: appMetadataList.map(metadata => {
      // Runtime validation for required fields
      if (!metadata.appName || !metadata.bundleId) {
        throw new Error(`Invalid app metadata: missing appName or bundleId`);
      }
      return {
        name: metadata.appName,
        bundleId: metadata.bundleId,
        description: metadata.description || 'No description available',
        toolCount: metadata.toolCount ?? 0,
        suites: metadata.suiteNames || [],
      };
    }),
  };
}

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

      // Use shared discovery function
      const appMetadataList = await discoverAppMetadata();

      // Store discovered apps for lazy loading in CallTool handler
      const apps = await findAllScriptableApps({ useCache: false });
      discoveredApps = apps;

      if (appMetadataList.length === 0) {
        console.error('[ListTools] No scriptable apps found');
        return {
          tools: [],
          _app_metadata: [],
        };
      }

      // MCP Tools for app discovery
      //
      // Note: We provide BOTH a tool and a resource for app listing:
      // - Resource (iac://apps): Loaded at session start, cached by client
      // - Tool (list_apps): Discoverable during conversation, can refresh mid-session
      //
      // This dual approach optimizes for both session initialization and ongoing discoverability.

      /**
       * get_app_tools Tool Definition
       *
       * Lazy loads MCP tools for a specific macOS application on demand.
       * Returns tool definitions and object model (classes/enumerations).
       * Uses per-app caching for performance.
       */
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

      /**
       * list_apps Tool Definition
       *
       * Returns metadata for all discovered scriptable macOS applications.
       * No parameters required. Returns JSON with app names, bundle IDs,
       * descriptions, tool counts, and suite names.
       *
       * Complements the iac://apps resource by providing discoverable
       * mid-conversation refresh capability.
       */
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
        // Defensive validation: ensure no unexpected arguments
        if (args && Object.keys(args).length > 0) {
          console.error('[CallTool/list_apps] Warning: Unexpected arguments provided, ignoring');
          // Continue anyway for forward compatibility
        }

        try {
          console.error('[CallTool/list_apps] Executing list_apps tool');

          // Use shared discovery function
          const appMetadataList = await discoverAppMetadata();

          // Use shared formatting function
          const response = formatAppMetadataResponse(appMetadataList);

          console.error(`[CallTool/list_apps] Returning ${response.totalApps} apps`);

          return {
            content: [{
              type: 'text' as const,
              text: JSON.stringify(response, null, 2),
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
        console.error('[CallTool/get_app_tools] Executing get_app_tools tool');

        // Validate app_name parameter
        const appName = args?.app_name as string | undefined;

        if (!appName) {
          console.error('[CallTool/get_app_tools] Error: Missing app_name parameter');
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
          console.error(`[CallTool/get_app_tools] Loading tools for app: ${appName}`);
          const appToolsResponse = await loadAppTools(
            appName,
            discoveredApps,
            sdefParser,
            toolGenerator,
            perAppCache
          );

          console.error(`[CallTool/get_app_tools] Successfully loaded ${appToolsResponse.tools.length} tools for ${appName}`);

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
              console.error(`[CallTool/get_app_tools] App not found: ${appName}`);
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
          console.error(`[CallTool/get_app_tools] Error loading tools for ${appName}: ${message}`);
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

  /**
   * ListResources Handler
   *
   * Returns available MCP resources for session initialization.
   * Resources provide static/semi-static data that clients can cache.
   */
  server.setRequestHandler(ListResourcesRequestSchema, async () => {
    try {
      console.error('[ListResources] Listing available resources');

      return {
        resources: [
          {
            uri: 'iac://apps',
            name: 'Available macOS Applications',
            description: 'List of all scriptable macOS applications with metadata (cached for session)',
            mimeType: 'application/json',
          },
        ],
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(`[ListResources] Error: ${message}`);
      return {
        resources: [],
        _error: message,
      };
    }
  });

  /**
   * ReadResource Handler
   *
   * Returns resource content for requested URI.
   * Uses shared discoverAppMetadata() for consistency with list_apps tool.
   */
  server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
    const { uri } = request.params;

    try {
      console.error(`[ReadResource] Reading resource: ${uri}`);

      // Validate URI (security: prevent path traversal, DoS)
      if (!uri || typeof uri !== 'string') {
        console.error('[ReadResource] Invalid URI: not a string');
        return {
          contents: [{
            uri: uri || '',
            mimeType: 'text/plain',
            text: 'Error: Invalid URI format',
          }],
        };
      }

      // Length limit to prevent DoS
      if (uri.length > 256) {
        console.error(`[ReadResource] URI too long: ${uri.length} characters`);
        return {
          contents: [{
            uri,
            mimeType: 'text/plain',
            text: 'Error: URI exceeds maximum length (256 characters)',
          }],
        };
      }

      // Whitelist known URI schemes
      if (!uri.startsWith('iac://')) {
        console.error(`[ReadResource] Unknown URI scheme: ${uri}`);
        return {
          contents: [{
            uri,
            mimeType: 'text/plain',
            text: `Error: Unknown URI scheme. Only 'iac://' URIs are supported.`,
          }],
        };
      }

      if (uri === 'iac://apps') {
        // Use shared discovery function (same as list_apps tool)
        const appMetadataList = await discoverAppMetadata();

        // Use shared formatting function
        const response = formatAppMetadataResponse(appMetadataList);

        console.error(`[ReadResource] Returning ${response.totalApps} apps for iac://apps`);

        return {
          contents: [{
            uri,
            mimeType: 'application/json',
            text: JSON.stringify(response, null, 2),
          }],
        };
      }

      // Unknown resource URI
      console.error(`[ReadResource] Unknown resource URI: ${uri}`);
      return {
        contents: [{
          uri,
          mimeType: 'text/plain',
          text: `Error: Unknown resource URI: ${uri}`,
        }],
      };

    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(`[ReadResource] Error reading ${uri}: ${message}`);

      return {
        contents: [{
          uri,
          mimeType: 'text/plain',
          text: `Error reading resource: ${message}`,
        }],
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

