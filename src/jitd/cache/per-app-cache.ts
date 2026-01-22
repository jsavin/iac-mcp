/**
 * Per-App Cache for Lazy Loading
 *
 * Provides disk-based caching of parsed SDEF files and generated MCP tools
 * on a per-application basis. Enables fast tool loading (<100ms) by avoiding
 * expensive SDEF parsing and tool generation on repeated requests.
 *
 * Cache location: ~/.cache/iac-mcp/apps/{bundleId}.json
 *
 * Cache includes:
 * - Parsed SDEF dictionary
 * - Generated MCP tools
 * - SDEF modification time (for cache invalidation)
 * - App bundle modification time (for cache invalidation)
 *
 * Phase 4 of lazy loading implementation.
 */

import { mkdir, writeFile, unlink, readFile } from 'fs/promises';
import { existsSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { z } from 'zod';
import type { SDEFDictionary } from '../../types/sdef.js';
import type { MCPTool } from '../../types/mcp-tool.js';

/**
 * Cache format version
 *
 * Increment when cache format changes to force cache invalidation.
 */
const CACHE_VERSION = '1.0.0';

/**
 * Zod schema for SDEF Type validation (discriminated union)
 */
const SDEFTypeSchema: z.ZodType<any> = z.lazy(() =>
  z.union([
    z.object({ kind: z.literal('primitive'), type: z.enum(['text', 'integer', 'real', 'boolean']) }),
    z.object({ kind: z.literal('file') }),
    z.object({ kind: z.literal('list'), itemType: SDEFTypeSchema }),
    z.object({ kind: z.literal('record'), properties: z.record(z.string(), SDEFTypeSchema) }),
    z.object({ kind: z.literal('class'), className: z.string() }),
    z.object({ kind: z.literal('enumeration'), enumerationName: z.string() }),
    z.object({ kind: z.literal('any') }),
    z.object({ kind: z.literal('missing_value') }),
    z.object({ kind: z.literal('type_class') }),
    z.object({ kind: z.literal('location_specifier') }),
    z.object({ kind: z.literal('color') }),
    z.object({ kind: z.literal('date') }),
    z.object({ kind: z.literal('property') }),
    z.object({ kind: z.literal('save_options') }),
  ])
);

/**
 * Zod schema for SDEF Parameter validation
 */
const SDEFParameterSchema = z.object({
  name: z.string(),
  code: z.string(),
  type: SDEFTypeSchema,
  description: z.string().optional(),
  optional: z.boolean().optional(),
});

/**
 * Zod schema for SDEF Command validation
 */
const SDEFCommandSchema = z.object({
  name: z.string(),
  code: z.string(),
  description: z.string().optional(),
  parameters: z.array(SDEFParameterSchema),
  result: SDEFTypeSchema.optional(),
  directParameter: SDEFParameterSchema.optional(),
});

/**
 * Zod schema for SDEF Property validation
 */
const SDEFPropertySchema = z.object({
  name: z.string(),
  code: z.string(),
  type: SDEFTypeSchema,
  description: z.string().optional(),
  access: z.enum(['r', 'w', 'rw']),
});

/**
 * Zod schema for SDEF Element validation
 */
const SDEFElementSchema = z.object({
  type: z.string(),
  access: z.enum(['r', 'w', 'rw']),
});

/**
 * Zod schema for SDEF Enumerator validation
 */
const SDEFEnumeratorSchema = z.object({
  name: z.string(),
  code: z.string(),
  description: z.string().optional(),
});

/**
 * Zod schema for SDEF Enumeration validation
 */
const SDEFEnumerationSchema = z.object({
  name: z.string(),
  code: z.string(),
  description: z.string().optional(),
  enumerators: z.array(SDEFEnumeratorSchema),
});

/**
 * Zod schema for SDEF Class validation
 */
const SDEFClassSchema = z.object({
  name: z.string(),
  code: z.string(),
  description: z.string().optional(),
  properties: z.array(SDEFPropertySchema),
  elements: z.array(SDEFElementSchema),
  inherits: z.string().optional(),
});

/**
 * Zod schema for SDEF Suite validation
 */
const SDEFSuiteSchema = z.object({
  name: z.string(),
  code: z.string(),
  description: z.string().optional(),
  commands: z.array(SDEFCommandSchema),
  classes: z.array(SDEFClassSchema),
  enumerations: z.array(SDEFEnumerationSchema),
});

/**
 * Zod schema for SDEF Dictionary validation
 */
const SDEFDictionarySchema = z.object({
  title: z.string(),
  suites: z.array(SDEFSuiteSchema),
});

/**
 * Zod schema for MCP Tool validation
 */
const MCPToolSchema = z.object({
  name: z.string(),
  description: z.string(),
  inputSchema: z.object({
    type: z.literal('object'),
    properties: z.record(z.string(), z.any()).optional(),
    required: z.array(z.string()).optional(),
  }),
});

/**
 * Schema for cache data validation
 */
const PerAppCacheDataSchema = z.object({
  appName: z.string(),
  bundleId: z.string(),
  sdefPath: z.string(),
  sdefModifiedTime: z.number(),
  bundleModifiedTime: z.number(),
  parsedSDEF: SDEFDictionarySchema,
  generatedTools: z.array(MCPToolSchema),
  cachedAt: z.number(),
  cacheVersion: z.string().optional(),
});

/**
 * Data stored in per-app cache file
 */
export interface PerAppCacheData {
  /**
   * Application name
   */
  appName: string;

  /**
   * Application bundle identifier
   */
  bundleId: string;

  /**
   * Path to SDEF file
   */
  sdefPath: string;

  /**
   * SDEF file modification time (ms since epoch)
   */
  sdefModifiedTime: number;

  /**
   * App bundle modification time (ms since epoch)
   */
  bundleModifiedTime: number;

  /**
   * Parsed SDEF dictionary
   */
  parsedSDEF: SDEFDictionary;

  /**
   * Generated MCP tools
   */
  generatedTools: MCPTool[];

  /**
   * Timestamp when cache was created (ms since epoch)
   */
  cachedAt: number;

  /**
   * Cache format version (for compatibility checks)
   */
  cacheVersion?: string;
}

/**
 * Per-app cache for storing parsed SDEF and generated tools
 *
 * Manages disk-based caching with automatic invalidation when
 * app bundles or SDEF files are modified.
 */
export class PerAppCache {
  private cacheDir: string;

  /**
   * Create a new PerAppCache
   *
   * @param cacheDir - Directory for cache files (default: ~/.cache/iac-mcp/apps)
   */
  constructor(cacheDir?: string) {
    this.cacheDir = cacheDir || join(homedir(), '.cache', 'iac-mcp', 'apps');
  }

  /**
   * Get the cache file path for a bundle ID
   *
   * @param bundleId - Application bundle identifier
   * @returns Absolute path to cache file
   * @throws Error if bundle ID contains invalid characters or path traversal sequences
   */
  getCachePath(bundleId: string): string {
    // Validate bundle ID follows reverse-DNS format (alphanumeric, dots, hyphens only)
    if (!/^[a-zA-Z0-9.-]+$/.test(bundleId)) {
      throw new Error(
        `Invalid bundle ID format: ${bundleId}. Must match reverse-DNS pattern (a-zA-Z0-9.-)`
      );
    }

    // Additional safety: reject path traversal attempts
    if (bundleId.includes('..') || bundleId.includes('/') || bundleId.includes('\\')) {
      throw new Error(`Bundle ID contains path traversal sequences: ${bundleId}`);
    }

    return join(this.cacheDir, `${bundleId}.json`);
  }

  /**
   * Load cached data for an application
   *
   * @param bundleId - Application bundle identifier
   * @returns Cached data or null if not found or corrupted
   */
  async load(bundleId: string): Promise<PerAppCacheData | null> {
    const cachePath = this.getCachePath(bundleId);

    // Check if cache file exists
    if (!existsSync(cachePath)) {
      return null;
    }

    try {
      // Read and parse cache file
      const content = await readFile(cachePath, 'utf-8');
      const parsedContent = JSON.parse(content);

      // Validate with zod schema
      const data = PerAppCacheDataSchema.parse(parsedContent);

      // Basic field checks (already validated by schema, but kept for clarity)
      if (!data.appName || !data.bundleId || !data.parsedSDEF || !data.generatedTools) {
        return null;
      }

      return data as PerAppCacheData;
    } catch (error) {
      // Gracefully handle validation errors
      if (error instanceof z.ZodError) {
        console.warn(
          `Cache validation failed for ${bundleId}:`,
          error.issues.map((e: z.ZodIssue) => `${e.path.join('.')}: ${e.message}`).join(', ')
        );
      }
      // Return null for any errors (missing file, invalid JSON, validation errors, etc.)
      return null;
    }
  }

  /**
   * Save cache data for an application
   *
   * @param bundleId - Application bundle identifier
   * @param data - Cache data to save
   */
  async save(bundleId: string, data: PerAppCacheData): Promise<void> {
    const cachePath = this.getCachePath(bundleId);

    // Ensure cache directory exists
    await mkdir(this.cacheDir, { recursive: true });

    // Add cache version to data
    const dataWithVersion: PerAppCacheData = {
      ...data,
      cacheVersion: CACHE_VERSION,
    };

    // Serialize and write to disk
    const content = JSON.stringify(dataWithVersion, null, 2);
    await writeFile(cachePath, content, 'utf-8');
  }

  /**
   * Check if cached data is still valid
   *
   * Validates by comparing modification times and cache version.
   *
   * @param bundleId - Application bundle identifier
   * @param currentSdefMtime - Current SDEF modification time
   * @param currentBundleMtime - Current bundle modification time
   * @returns true if cache is valid, false otherwise
   */
  async isValid(
    bundleId: string,
    currentSdefMtime: number,
    currentBundleMtime: number
  ): Promise<boolean> {
    const cached = await this.load(bundleId);

    if (!cached) {
      return false;
    }

    // Check cache version
    if (cached.cacheVersion !== CACHE_VERSION) {
      return false;
    }

    // Check SDEF modification time
    if (cached.sdefModifiedTime !== currentSdefMtime) {
      return false;
    }

    // Check bundle modification time
    if (cached.bundleModifiedTime !== currentBundleMtime) {
      return false;
    }

    return true;
  }

  /**
   * Invalidate (delete) cache for an application
   *
   * @param bundleId - Application bundle identifier
   */
  async invalidate(bundleId: string): Promise<void> {
    const cachePath = this.getCachePath(bundleId);

    try {
      await unlink(cachePath);
    } catch (error) {
      // Ignore errors (file might not exist)
    }
  }
}
