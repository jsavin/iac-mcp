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
} from '@modelcontextprotocol/sdk/types.js';
import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import type { PermissionDecision } from '../permissions/types.js';
import type { ToolGenerator } from '../jitd/tool-generator/generator.js';
import type { MacOSAdapter } from '../adapters/macos/macos-adapter.js';
import type { PermissionChecker } from '../permissions/permission-checker.js';
import type { ErrorHandler } from '../error-handler.js';
import type { ToolCache } from '../jitd/cache/tool-cache.js';
import type { MCPTool } from '../types/mcp-tool.js';
import type { CacheManifest } from '../jitd/cache/tool-cache.js';
import { CACHE_VERSION } from '../jitd/cache/tool-cache.js';
import { findAllScriptableApps } from '../jitd/discovery/find-sdef.js';
import { sdefParser } from '../jitd/discovery/parse-sdef.js';

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
  errorHandler: ErrorHandler,
  toolCache: ToolCache
): Promise<void> {
  // Initialize resource cache for app dictionaries
  const resourceCache: ResourceCache = new Map();

  // Store discovered tools in memory for CallTool lookups
  let discoveredTools: MCPTool[] = [];

  /**
   * ListTools Handler
   *
   * Called by MCP clients to discover available tools.
   * Generates tools from JITD engine and returns them in MCP format.
   */
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    try {
      console.error('[ListTools] Starting tool discovery');

      // Try to load from cache first
      const cachedManifest = await toolCache.load();

      if (cachedManifest) {
        console.error(`[ListTools] Loaded ${cachedManifest.apps.length} apps from cache`);

        // Validate cache and collect valid tools
        const validTools: MCPTool[] = [];
        const invalidApps: string[] = [];

        for (const cachedApp of cachedManifest.apps) {
          const isValid = await toolCache.isValid(cachedApp);
          if (isValid) {
            validTools.push(...cachedApp.generatedTools);
          } else {
            invalidApps.push(cachedApp.appName);
          }
        }

        // If all cached apps are valid, use cache
        if (invalidApps.length === 0) {
          console.error(`[ListTools] Cache is valid, returning ${validTools.length} tools`);
          discoveredTools = validTools;

          return {
            tools: validTools.map(tool => ({
              name: tool.name,
              description: tool.description,
              inputSchema: tool.inputSchema as any, // MCP SDK type is slightly different
            })),
          };
        }

        console.error(`[ListTools] Cache partially invalid (${invalidApps.join(', ')}), regenerating`);
      } else {
        console.error('[ListTools] No cache found, discovering apps');
      }

      // Discover all scriptable apps
      const apps = await findAllScriptableApps({ useCache: false });
      console.error(`[ListTools] Discovered ${apps.length} scriptable apps`);

      if (apps.length === 0) {
        console.error('[ListTools] No scriptable apps found');
        discoveredTools = [];
        return { tools: [] };
      }

      // Parse SDEF files and generate tools for each app
      const allTools: MCPTool[] = [];
      const cacheManifest: CacheManifest = {
        version: CACHE_VERSION,
        cachedAt: Date.now(),
        apps: [],
      };

      for (const app of apps) {
        try {
          console.error(`[ListTools] Processing ${app.appName}`);

          // Parse SDEF
          const dictionary = await sdefParser.parse(app.sdefPath);

          // Get bundle ID from SDEF title or use a fallback
          const bundleId = dictionary.title || `com.unknown.${app.appName.toLowerCase()}`;

          // Create AppInfo for tool generator
          const appInfo = {
            appName: app.appName,
            bundleId,
            bundlePath: app.bundlePath,
            sdefPath: app.sdefPath,
          };

          // Generate tools
          const tools = toolGenerator.generateTools(dictionary, appInfo);
          console.error(`[ListTools] Generated ${tools.length} tools for ${app.appName}`);

          allTools.push(...tools);

          // Get file stats for caching
          const { stat } = await import('fs/promises');
          const bundleStats = await stat(app.bundlePath);
          const sdefStats = await stat(app.sdefPath);

          // Add to cache manifest
          cacheManifest.apps.push({
            appName: app.appName,
            bundlePath: app.bundlePath,
            bundleId,
            sdefPath: app.sdefPath,
            sdefModifiedTime: sdefStats.mtimeMs,
            bundleModifiedTime: bundleStats.mtimeMs,
            parsedSDEF: dictionary,
            generatedTools: tools,
            cachedAt: Date.now(),
          });

        } catch (error) {
          const errorMsg = error instanceof Error ? error.message : String(error);
          console.error(`[ListTools] Failed to process ${app.appName}: ${errorMsg}`);
          // Continue with other apps
        }
      }

      console.error(`[ListTools] Total tools generated: ${allTools.length}`);

      // Save to cache for next startup
      await toolCache.save(cacheManifest);

      // Store tools for CallTool handler
      discoveredTools = allTools;

      // Return tools in MCP format (without _metadata)
      const tools: Tool[] = allTools.map(tool => ({
        name: tool.name,
        description: tool.description,
        inputSchema: tool.inputSchema as any, // MCP SDK type is slightly different
      }));

      return { tools };

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
      console.error(`[CallTool] Executing tool: ${toolName}`);

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
   * ListResources Handler (Optional)
   *
   * Called by MCP clients to discover available resources.
   * Returns app dictionary resources for each discovered app.
   */
  server.setRequestHandler(ListResourcesRequestSchema, async () => {
    try {
      console.error('[ListResources] Listing available resources');

      // Generate resources from discovered tools
      const resources = discoveredTools
        .map(tool => {
          const bundleId = tool._metadata?.bundleId;
          const appName = tool._metadata?.appName;

          if (!bundleId || !appName) {
            return null;
          }

          const uri = `iac://apps/${bundleId}/dictionary`;
          return {
            uri,
            name: `${appName} Dictionary`,
            description: `Complete SDEF dictionary for ${appName} with all commands`,
            mimeType: 'application/json',
          };
        })
        .filter((r): r is NonNullable<typeof r> => r !== null)
        // Remove duplicates (multiple tools from same app)
        .filter((resource, index, self) =>
          self.findIndex(r => r.uri === resource.uri) === index
        );

      console.error(`[ListResources] Returning ${resources.length} resources`);

      return { resources };

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
   * ReadResource Handler (Optional)
   *
   * Called by MCP clients to retrieve a specific resource.
   * Returns parsed SDEF dictionary for an app.
   */
  server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
    const { uri } = request.params;

    try {
      console.error(`[ReadResource] Reading resource: ${uri}`);

      // Check cache first
      const cached = resourceCache.get(uri);
      if (cached) {
        console.error(`[ReadResource] Cache hit for ${uri}`);
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

      // Parse URI: iac://apps/{bundleId}/dictionary
      const match = uri.match(/^iac:\/\/apps\/([^/]+)\/dictionary$/);
      if (!match) {
        console.error(`[ReadResource] Invalid URI format: ${uri}`);
        return {
          contents: [
            {
              uri,
              mimeType: 'application/json',
              text: JSON.stringify({
                error: 'Invalid URI format. Expected: iac://apps/{bundleId}/dictionary',
                uri,
              }),
            },
          ],
        };
      }

      const bundleId = match[1];

      // Find all tools for this app
      const appTools = discoveredTools.filter(
        t => t._metadata?.bundleId === bundleId
      );

      if (appTools.length === 0) {
        console.error(`[ReadResource] No tools found for bundleId: ${bundleId}`);
        return {
          contents: [
            {
              uri,
              mimeType: 'application/json',
              text: JSON.stringify({
                error: 'Resource not found',
                bundleId,
                uri,
              }),
            },
          ],
        };
      }

      // Format as LLM-friendly dictionary
      const appName = appTools[0]?._metadata?.appName || 'Unknown';
      const dictionary = {
        appName,
        bundleId,
        commands: appTools.map(tool => ({
          tool: tool.name,
          description: tool.description,
          parameters: Object.entries(tool.inputSchema.properties || {}).reduce(
            (acc, [key, value]) => {
              acc[key] = {
                type: value.type,
                description: value.description,
                required: tool.inputSchema.required?.includes(key) || false,
              };
              return acc;
            },
            {} as Record<string, any>
          ),
        })),
      };

      const content = JSON.stringify(dictionary, null, 2);

      // Cache the result
      resourceCache.set(uri, {
        uri,
        name: `${appName} Dictionary`,
        content,
      });

      console.error(`[ReadResource] Returning dictionary for ${appName} (${appTools.length} commands)`);

      return {
        contents: [
          {
            uri,
            mimeType: 'application/json',
            text: content,
          },
        ],
      };

    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(`[ReadResource] Error: ${message}`);
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
