/**
 * Naming Utility Module
 *
 * Generates MCP-compliant tool and parameter names from SDEF commands.
 * Handles normalization, collision detection/resolution, and truncation.
 *
 * @module naming
 */

import { createHash } from 'crypto';
import type { SDEFCommand } from '../../types/sdef.js';
import type { NamingOptions } from '../../types/tool-generator.js';
import { CollisionResolutionError } from './errors.js';
import {
  DEFAULT_MAX_TOOL_NAME_LENGTH,
  MAX_COLLISION_RESOLUTION_ATTEMPTS,
  HASH_SUFFIX_LENGTH,
} from './constants.js';

/**
 * Utility class for generating and managing tool and parameter names
 *
 * Responsibilities:
 * - Generate MCP-compliant tool names from SDEF commands
 * - Sanitize parameter names
 * - Detect and resolve naming collisions
 * - Handle normalization, truncation, and edge cases
 *
 * @example
 * ```typescript
 * const naming = new NamingUtility();
 * const command = { name: 'open', code: 'aevtodoc', parameters: [] };
 * const toolName = naming.generateToolName(command, 'Finder');
 * // Returns: "finder_open"
 * ```
 */
export class NamingUtility {
  private readonly strategy: 'app_prefix' | 'suite_prefix' | 'fully_qualified';
  private readonly maxLength: number;
  private readonly useHashForTruncation: boolean;

  /**
   * Create a new NamingUtility instance
   *
   * @param options - Configuration options
   * @param options.strategy - Naming strategy ('app_prefix', 'suite_prefix', 'fully_qualified')
   * @param options.maxLength - Maximum tool name length (default: 64)
   * @param options.useHashForTruncation - Append hash suffix when truncating (default: true)
   */
  constructor(options?: NamingOptions) {
    this.strategy = options?.strategy ?? 'app_prefix';
    this.maxLength = options?.maxLength ?? DEFAULT_MAX_TOOL_NAME_LENGTH;
    this.useHashForTruncation = options?.useHashForTruncation ?? true;
  }

  /**
   * Generate a tool name from a command and app name
   *
   * Combines app name, optional suite name, and command name according to
   * the configured naming strategy. Handles normalization and truncation.
   *
   * @param command - SDEF command definition
   * @param appName - Application name (e.g., "Finder")
   * @param suiteName - Optional suite name (e.g., "Standard Suite")
   * @returns Normalized tool name (e.g., "finder_open")
   *
   * @example
   * ```typescript
   * const naming = new NamingUtility({ strategy: 'app_prefix' });
   * const command = { name: 'open file', code: 'openfile', parameters: [] };
   * const toolName = naming.generateToolName(command, 'Finder');
   * // Returns: "finder_open_file"
   * ```
   */
  generateToolName(
    command: SDEFCommand,
    appName: string,
    suiteName?: string
  ): string {
    const normalizedApp = this.normalize(appName);
    const normalizedCommand = this.normalize(command.name);

    // Handle empty or invalid command names
    let finalCommandName = normalizedCommand;
    if (!finalCommandName) {
      // Use code as fallback, or default to "command"
      finalCommandName = command.code ? this.normalize(command.code) : 'command';
    }

    let toolName: string;

    switch (this.strategy) {
      case 'app_prefix':
        // Default: app_command (e.g., "finder_open")
        if (suiteName) {
          const normalizedSuite = this.normalize(suiteName);
          toolName = `${normalizedApp}_${normalizedSuite}_${finalCommandName}`;
        } else {
          toolName = `${normalizedApp}_${finalCommandName}`;
        }
        break;

      case 'suite_prefix':
        // Suite first: suite_command (e.g., "standard_suite_open")
        if (suiteName) {
          const normalizedSuite = this.normalize(suiteName);
          toolName = `${normalizedSuite}_${finalCommandName}`;
        } else {
          // Fallback to app_prefix if no suite
          toolName = `${normalizedApp}_${finalCommandName}`;
        }
        break;

      case 'fully_qualified':
        // Full path: app_suite_command (e.g., "finder_standard_suite_open")
        if (suiteName) {
          const normalizedSuite = this.normalize(suiteName);
          toolName = `${normalizedApp}_${normalizedSuite}_${finalCommandName}`;
        } else {
          toolName = `${normalizedApp}_${finalCommandName}`;
        }
        break;
    }

    return this.truncate(toolName);
  }

  /**
   * Sanitize a parameter name for use in JSON schema
   *
   * Converts spaces to underscores, removes special characters,
   * collapses multiple underscores, and converts to lowercase.
   *
   * @param name - Raw parameter name from SDEF
   * @returns Sanitized parameter name
   *
   * @example
   * ```typescript
   * naming.sanitizeParameterName('with properties');
   * // Returns: "with_properties"
   *
   * naming.sanitizeParameterName('file-name!@#');
   * // Returns: "file_name"
   * ```
   */
  sanitizeParameterName(name: string): string {
    if (!name) {
      return 'param';
    }

    const sanitized = name
      .replace(/\s+/g, '_') // Convert spaces to underscores
      .replace(/[^a-z0-9_]/gi, '_') // Replace special chars with underscores
      .toLowerCase() // Convert to lowercase
      .replace(/_+/g, '_') // Collapse multiple underscores
      .replace(/^_|_$/g, ''); // Remove leading/trailing underscores

    // Handle case where everything was stripped
    if (!sanitized) {
      return 'param';
    }

    return sanitized;
  }

  /**
   * Check if a name collides with existing tools
   *
   * Performs case-sensitive comparison.
   *
   * @param name - Name to check
   * @param existingTools - Array of existing tools with name property
   * @returns True if collision exists, false otherwise
   */
  checkNameCollision(name: string, existingTools: { name: string }[]): boolean {
    return existingTools.some((tool) => tool.name === name);
  }

  /**
   * Resolve a naming collision
   *
   * Strategy:
   * 1. If no collision exists, return original name
   * 2. If suite name provided, append normalized suite name
   * 3. Otherwise, append incrementing numeric suffix (_1, _2, etc.)
   *
   * @param baseName - Base name that collides
   * @param existingTools - Array of existing tools
   * @param suiteName - Optional suite name for collision resolution
   * @returns Unique tool name
   *
   * @example
   * ```typescript
   * const existing = [{ name: 'finder_open' }];
   * const resolved = naming.resolveCollision('finder_open', existing, 'Standard Suite');
   * // Returns: "finder_standard_suite_open"
   * ```
   */
  resolveCollision(
    baseName: string,
    existingTools: { name: string }[],
    suiteName?: string
  ): string {
    // No collision - return original name
    if (!this.checkNameCollision(baseName, existingTools)) {
      return baseName;
    }

    // Strategy 1: Try appending suite name
    if (suiteName) {
      const normalizedSuite = this.normalize(suiteName);
      // Parse base name to insert suite before command
      const parts = baseName.split('_');
      if (parts.length >= 2) {
        // Reconstruct: app_suite_command
        const withSuite = `${parts.slice(0, -1).join('_')}_${normalizedSuite}_${parts[parts.length - 1]}`;
        if (!this.checkNameCollision(withSuite, existingTools)) {
          return this.truncate(withSuite);
        }
      } else {
        // Single part name - just append suite
        const withSuite = `${baseName}_${normalizedSuite}`;
        if (!this.checkNameCollision(withSuite, existingTools)) {
          return this.truncate(withSuite);
        }
      }
    }

    // Strategy 2: Append incrementing number
    let counter = 1;
    let candidate: string;
    do {
      candidate = `${baseName}_${counter}`;
      counter++;
    } while (
      this.checkNameCollision(candidate, existingTools) &&
      counter < MAX_COLLISION_RESOLUTION_ATTEMPTS
    );

    // If we hit the limit, throw an error instead of returning a colliding name
    if (counter >= MAX_COLLISION_RESOLUTION_ATTEMPTS) {
      throw new CollisionResolutionError(
        `Unable to resolve name collision for "${baseName}" after ${MAX_COLLISION_RESOLUTION_ATTEMPTS} attempts`,
        baseName
      );
    }

    return this.truncate(candidate);
  }

  /**
   * Normalize a name to valid format
   *
   * Rules:
   * - Convert to lowercase
   * - Replace non-alphanumeric characters with underscores
   * - Collapse multiple underscores into one
   * - Remove leading/trailing underscores
   * - Ensure doesn't start with a number (prefix with 'n' if needed)
   *
   * @param name - Raw name to normalize
   * @returns Normalized name
   * @private
   */
  private normalize(name: string): string {
    if (!name) {
      return '';
    }

    const normalized = name
      .toLowerCase()
      .replace(/[^a-z0-9_]/g, '_') // Replace non-alphanumeric with underscore
      .replace(/_+/g, '_') // Collapse multiple underscores
      .replace(/^_|_$/g, ''); // Remove leading/trailing underscores

    // Ensure doesn't start with a number
    if (normalized && /^[0-9]/.test(normalized)) {
      return `n${normalized}`;
    }

    return normalized;
  }

  /**
   * Truncate a name to maximum length
   *
   * If name exceeds maxLength:
   * - With hashing enabled: Truncate to (maxLength - hashLength - 1) and append hash
   * - Without hashing: Simple truncation
   *
   * @param name - Name to truncate
   * @returns Truncated name
   * @private
   */
  private truncate(name: string): string {
    if (name.length <= this.maxLength) {
      return name;
    }

    if (this.useHashForTruncation) {
      const hash = this.generateHash(name);
      const availableLength = this.maxLength - hash.length - 1; // -1 for underscore
      const truncated = name.substring(0, availableLength);
      return `${truncated}_${hash}`;
    }

    return name.substring(0, this.maxLength);
  }

  /**
   * Generate a hash for uniqueness in truncated names
   *
   * Uses SHA-256 cryptographic hash to ensure collision resistance.
   * Returns first 8 characters of the hex digest, providing 32 bits
   * of entropy (much better than the previous 32-bit hash).
   *
   * @param text - Text to hash
   * @returns Hash string (8 characters, hexadecimal)
   * @private
   */
  private generateHash(text: string): string {
    return createHash('sha256')
      .update(text)
      .digest('hex')
      .substring(0, HASH_SUFFIX_LENGTH);
  }
}
