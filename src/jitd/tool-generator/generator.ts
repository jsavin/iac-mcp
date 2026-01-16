/**
 * Tool Generator Module
 *
 * Main orchestration class that combines all tool generator components to create
 * complete MCP tool definitions from SDEF data.
 *
 * The ToolGenerator coordinates:
 * - TypeMapper: Converts SDEF types to JSON Schema types
 * - NamingUtility: Generates MCP-compliant tool names
 * - SchemaBuilder: Constructs input schemas from parameters
 * - ToolValidator: Validates generated tools
 *
 * It supports three levels of tool generation:
 * 1. Single command → single tool
 * 2. Suite → multiple tools
 * 3. Full dictionary → all tools
 *
 * Generated tools are cached by bundle ID to avoid redundant processing.
 *
 * @example
 * ```typescript
 * const generator = new ToolGenerator({ strictValidation: true });
 *
 * const appInfo: AppInfo = {
 *   appName: 'Finder',
 *   bundleId: 'com.apple.finder',
 *   bundlePath: '/System/Library/CoreServices/Finder.app',
 *   sdefPath: '/System/Library/CoreServices/Finder.app/Contents/Resources/Finder.sdef'
 * };
 *
 * // Generate single tool
 * const tool = generator.generateTool(command, appInfo, 'Standard Suite');
 *
 * // Generate all tools from dictionary
 * const tools = generator.generateTools(dictionary, appInfo);
 * ```
 */

import type { SDEFCommand, SDEFSuite, SDEFDictionary } from '../../types/sdef.js';
import type { MCPTool } from '../../types/mcp-tool.js';
import type { ToolGeneratorOptions, AppInfo } from '../../types/tool-generator.js';
import { TypeMapper } from './type-mapper.js';
import { NamingUtility } from './naming.js';
import { SchemaBuilder } from './schema-builder.js';
import { ToolValidator } from './validator.js';
import { ValidationError, InvalidInputError } from './errors.js';
import { DEFAULT_CACHE_SIZE, DEFAULT_MAX_DESCRIPTION_LENGTH } from './constants.js';

/**
 * Simple LRU Cache implementation
 *
 * Provides basic caching with LRU eviction when max size is reached.
 */
class LRUCache<K, V> {
  private readonly maxSize: number;
  private readonly cache: Map<K, V>;

  constructor(maxSize: number = 1000) {
    this.maxSize = maxSize;
    this.cache = new Map();
  }

  get(key: K): V | undefined {
    const value = this.cache.get(key);
    if (value !== undefined) {
      // Move to end (most recently used)
      this.cache.delete(key);
      this.cache.set(key, value);
    }
    return value;
  }

  set(key: K, value: V): void {
    // Remove if already exists (we'll re-add at end)
    if (this.cache.has(key)) {
      this.cache.delete(key);
    }
    // Evict oldest if at capacity
    else if (this.cache.size >= this.maxSize) {
      const firstKey = this.cache.keys().next().value;
      if (firstKey !== undefined) {
        this.cache.delete(firstKey);
      }
    }
    this.cache.set(key, value);
  }

  clear(): void {
    this.cache.clear();
  }

  get size(): number {
    return this.cache.size;
  }
}

/**
 * Tool Generator
 *
 * Main class that orchestrates tool generation from SDEF data.
 * Combines TypeMapper, NamingUtility, SchemaBuilder, and ToolValidator
 * to produce valid MCP tool definitions.
 *
 * Features:
 * - Multi-level tool generation (command, suite, dictionary)
 * - Automatic name collision resolution
 * - Input validation with detailed error reporting
 * - LRU caching by bundle ID
 * - Configurable behavior via options
 */
export class ToolGenerator {
  private readonly typeMapper: TypeMapper;
  private readonly namingUtility: NamingUtility;
  private readonly schemaBuilder: SchemaBuilder;
  private readonly validator: ToolValidator;
  private readonly options: ToolGeneratorOptions;
  private readonly toolCache: LRUCache<string, MCPTool[]>;

  /**
   * Create a new ToolGenerator
   *
   * @param options - Optional configuration options
   * @param options.namingStrategy - How to generate tool names (default: 'app_prefix')
   * @param options.includeHiddenCommands - Include hidden commands (default: false)
   * @param options.maxDescriptionLength - Max description length (default: 500)
   * @param options.strictValidation - Enable strict validation (default: false)
   */
  constructor(options?: ToolGeneratorOptions) {
    this.options = {
      namingStrategy: options?.namingStrategy ?? 'app_prefix',
      includeHiddenCommands: options?.includeHiddenCommands ?? false,
      maxDescriptionLength: options?.maxDescriptionLength ?? DEFAULT_MAX_DESCRIPTION_LENGTH,
      strictValidation: options?.strictValidation ?? false,
    };

    // Initialize components
    this.typeMapper = new TypeMapper({
      strictTypeChecking: this.options.strictValidation,
    });

    this.namingUtility = new NamingUtility({
      strategy: this.options.namingStrategy,
    });

    this.schemaBuilder = new SchemaBuilder(this.typeMapper, {
      maxDescriptionLength: this.options.maxDescriptionLength,
    });

    this.validator = new ToolValidator();

    // Initialize cache
    this.toolCache = new LRUCache<string, MCPTool[]>(DEFAULT_CACHE_SIZE);
  }

  /**
   * Generate a single MCP tool from an SDEF command
   *
   * Converts a command definition into a complete MCP tool with:
   * - Generated tool name (using NamingUtility)
   * - Command description (or generated if missing)
   * - Input schema (built from parameters using SchemaBuilder)
   * - Metadata for execution layer
   *
   * @param command - SDEF command definition
   * @param appInfo - Application information
   * @param suiteName - Optional suite name for metadata
   * @returns Complete MCP tool definition
   * @throws Error if command has empty code (always throws, regardless of strictValidation)
   * @throws Error if command has empty name and strictValidation is enabled
   */
  generateTool(command: SDEFCommand, appInfo: AppInfo, suiteName?: string): MCPTool {
    // Validate appInfo
    if (!appInfo.appName || appInfo.appName.trim() === '') {
      throw new InvalidInputError('appInfo.appName cannot be empty', 'appName');
    }
    if (!appInfo.bundleId || appInfo.bundleId.trim() === '') {
      throw new InvalidInputError('appInfo.bundleId cannot be empty', 'bundleId');
    }

    // Always validate command code (required for execution)
    if (!command.code || command.code.trim() === '') {
      throw new ValidationError(
        `Command "${command.name}" has empty code`,
        'code',
        'critical'
      );
    }

    // Optionally validate command name
    if (this.options.strictValidation && (!command.name || command.name.trim() === '')) {
      throw new ValidationError('Command has empty name', 'name', 'critical');
    }

    // Generate tool name - only pass suiteName if strategy needs it
    const suiteNameForNaming =
      this.options.namingStrategy === 'app_prefix' ? undefined : suiteName;
    const toolName = this.namingUtility.generateToolName(
      command,
      appInfo.appName,
      suiteNameForNaming
    );

    // Generate or use description
    let description: string = command.description || '';
    if (!description || description.trim() === '') {
      // Generate description from command name
      description = `Execute ${command.name} command`;
    }

    // Truncate description if needed
    const maxLen = this.options.maxDescriptionLength;
    if (maxLen && description.length > maxLen) {
      description = description.substring(0, maxLen - 3) + '...';
    }

    // Build input schema
    const inputSchema = this.schemaBuilder.buildInputSchema(command);

    // Ensure required array is always present (even if empty)
    if (!inputSchema.required) {
      inputSchema.required = [];
    }

    // Determine direct parameter name if present
    const directParameterName = command.directParameter
      ? this.schemaBuilder.getDirectParameterName()
      : undefined;

    // Create tool
    const tool: MCPTool = {
      name: toolName,
      description,
      inputSchema,
      _metadata: {
        appName: appInfo.appName,
        bundleId: appInfo.bundleId,
        commandName: command.name,
        commandCode: command.code,
        suiteName: suiteName ?? '',
        directParameterName,
        resultType: command.result,
      },
    };

    // Validate tool
    const validationResult = this.validator.validate(tool);
    if (!validationResult.valid) {
      const errorMessages = validationResult.errors.map((e) => `${e.field}: ${e.message}`).join(', ');
      if (this.options.strictValidation) {
        throw new Error(`Invalid tool generated: ${errorMessages}`);
      } else {
        console.warn(`Warning: Tool "${toolName}" has validation errors: ${errorMessages}`);
      }
    }

    return tool;
  }

  /**
   * Generate all MCP tools from a suite
   *
   * Processes all commands in a suite and generates corresponding tools.
   * Critical errors (like empty command code) always throw.
   * Validation errors throw only in strict mode, otherwise skip with warning.
   *
   * @param suite - SDEF suite definition
   * @param appInfo - Application information
   * @returns Array of generated MCP tools
   * @throws Error if any command has critical errors (empty code) or strictValidation is enabled
   */
  generateToolsForSuite(suite: SDEFSuite, appInfo: AppInfo): MCPTool[] {
    const tools: MCPTool[] = [];

    for (const command of suite.commands) {
      try {
        const tool = this.generateTool(command, appInfo, suite.name);
        tools.push(tool);
      } catch (error) {
        // Critical ValidationErrors and InvalidInputErrors always throw
        if (error instanceof ValidationError && error.isCritical()) {
          throw error;
        }
        if (error instanceof InvalidInputError) {
          throw error;
        }

        // Other errors: throw in strict mode, warn otherwise
        if (this.options.strictValidation) {
          throw error;
        } else {
          const errorMessage = error instanceof Error ? error.message : String(error);
          console.warn(
            `Warning: Failed to generate tool for command "${command.name}" in suite "${suite.name}": ${errorMessage}`
          );
        }
      }
    }

    return tools;
  }

  /**
   * Generate all MCP tools from a dictionary
   *
   * Processes all suites and commands in a dictionary to generate all tools.
   * Results are cached by bundle ID to avoid redundant processing.
   *
   * Automatic name collision resolution ensures all tool names are unique
   * across the entire dictionary.
   *
   * @param dictionary - Complete SDEF dictionary
   * @param appInfo - Application information
   * @returns Array of all generated MCP tools
   */
  generateTools(dictionary: SDEFDictionary, appInfo: AppInfo): MCPTool[] {
    // Check cache first
    const cacheKey = appInfo.bundleId;
    const cached = this.toolCache.get(cacheKey);
    if (cached) {
      return cached;
    }

    const allTools: MCPTool[] = [];

    try {
      // Generate tools for each suite
      for (const suite of dictionary.suites) {
        const suiteTools = this.generateToolsForSuite(suite, appInfo);
        allTools.push(...suiteTools);
      }

      // Ensure all tool names are unique
      const uniqueTools: MCPTool[] = [];

      for (const tool of allTools) {
        if (uniqueTools.some((t) => t.name === tool.name)) {
          // Name collision - resolve using suite name from metadata
          const originalName = tool.name;
          const suiteName = tool._metadata?.suiteName;
          const uniqueName = this.namingUtility.resolveCollision(
            tool.name,
            uniqueTools,
            suiteName
          );

          // Update tool name
          tool.name = uniqueName;

          if (!this.options.strictValidation) {
            console.warn(`Resolved name collision: "${originalName}" → "${uniqueName}"`);
          }
        }
        uniqueTools.push(tool);
      }

      // Cache the results
      this.toolCache.set(cacheKey, uniqueTools);

      return uniqueTools;
    } catch (error) {
      // Don't cache failed generations
      throw error;
    }
  }

  /**
   * Clear the tool cache
   *
   * Removes all cached tool definitions. Useful when you want to force
   * regeneration of tools (e.g., after updating SDEF data).
   */
  clearCache(): void {
    this.toolCache.clear();
  }

  /**
   * Get cache statistics
   *
   * Returns information about the current cache state.
   *
   * @returns Cache statistics including size and max size
   */
  getCacheStats(): { size: number; maxSize: number } {
    return {
      size: this.toolCache.size,
      maxSize: 1000,
    };
  }
}

// Re-export types for convenience
export type { AppInfo, ToolGeneratorOptions };
