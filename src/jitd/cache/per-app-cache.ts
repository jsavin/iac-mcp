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
import type { SDEFDictionary } from '../../types/sdef.js';
import type { MCPTool } from '../../types/mcp-tool.js';

/**
 * Cache format version
 *
 * Increment when cache format changes to force cache invalidation.
 */
const CACHE_VERSION = '1.0.0';

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
   */
  getCachePath(bundleId: string): string {
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
      const data = JSON.parse(content) as PerAppCacheData;

      // Verify cache has required fields
      if (!data.appName || !data.bundleId || !data.parsedSDEF || !data.generatedTools) {
        return null;
      }

      return data;
    } catch (error) {
      // Return null for any errors (missing file, invalid JSON, etc.)
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
