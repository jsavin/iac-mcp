/**
 * Tool Cache for JITD
 *
 * Stores parsed SDEF data and generated tools to avoid re-parsing on every startup.
 * Invalidates cache when app bundle is modified.
 */

import fs from 'fs';
import path from 'path';
import os from 'os';
import type { MCPTool } from '../../types/mcp-tool.js';
import type { SDEFDictionary } from '../../types/sdef.js';

/**
 * Cache version for invalidation when format changes
 */
export const CACHE_VERSION = '1.0.0';

/**
 * Cached data for a single application
 */
export interface CachedAppData {
  appName: string;
  bundleId: string;
  bundlePath: string;
  sdefPath: string;
  sdefModifiedTime: number;      // Unix timestamp (ms)
  bundleModifiedTime: number;    // Unix timestamp (ms)
  parsedSDEF: SDEFDictionary;
  generatedTools: MCPTool[];
  cachedAt: number;              // Unix timestamp (ms)
}

/**
 * Manifest of all cached app data
 */
export interface CacheManifest {
  version: string;
  cachedAt: number;
  apps: CachedAppData[];
}

/**
 * Tool Cache - Manages caching of parsed SDEF data and generated tools
 */
export class ToolCache {
  private cacheDir: string;
  private cacheFile: string;

  constructor(cacheDir?: string) {
    this.cacheDir = cacheDir ?? path.join(os.tmpdir(), 'iac-mcp-cache');
    this.cacheFile = path.join(this.cacheDir, 'tool-cache.json');
  }

  /**
   * Load cached data if valid
   *
   * @returns Cached data or null if invalid/missing
   */
  async load(): Promise<CacheManifest | null> {
    try {
      if (!fs.existsSync(this.cacheFile)) {
        console.error('[ToolCache] Cache file does not exist');
        return null;
      }

      console.error('[ToolCache] Starting cache load');
      const data = await fs.promises.readFile(this.cacheFile, 'utf-8');
      const manifest: CacheManifest = JSON.parse(data);

      // Validate cache version
      if (manifest.version !== CACHE_VERSION) {
        console.error('[ToolCache] Cache version mismatch, invalidating');
        return null;
      }

      console.error('[ToolCache] Cache loaded successfully');
      return manifest;
    } catch (error) {
      console.error('[ToolCache] Failed to load cache:', error);
      return null;
    }
  }

  /**
   * Save cache to disk
   *
   * @param manifest - Cache manifest to save
   */
  async save(manifest: CacheManifest): Promise<void> {
    try {
      console.error('[ToolCache] Starting cache save');

      // Ensure cache directory exists
      await fs.promises.mkdir(this.cacheDir, { recursive: true });

      // Write cache file
      await fs.promises.writeFile(
        this.cacheFile,
        JSON.stringify(manifest, null, 2),
        'utf-8'
      );

      console.error('[ToolCache] Cache saved successfully');
    } catch (error) {
      console.error('[ToolCache] Failed to save cache:', error);
    }
  }

  /**
   * Check if cached app data is still valid
   *
   * @param cached - Cached app data
   * @returns True if cache is valid, false if stale
   */
  async isValid(cached: CachedAppData): Promise<boolean> {
    try {
      // Check if app bundle still exists
      const bundleStat = await fs.promises.stat(cached.bundlePath);
      const sdefStat = await fs.promises.stat(cached.sdefPath);

      // Invalidate if modification times changed
      if (bundleStat.mtimeMs !== cached.bundleModifiedTime) {
        console.error('[ToolCache] Bundle modification time changed, invalidating');
        return false;
      }

      if (sdefStat.mtimeMs !== cached.sdefModifiedTime) {
        console.error('[ToolCache] SDEF modification time changed, invalidating');
        return false;
      }

      return true;
    } catch {
      // If files don't exist, cache is invalid
      console.error('[ToolCache] File stat failed, cache is invalid');
      return false;
    }
  }

  /**
   * Invalidate cache (delete cache file)
   */
  async invalidate(): Promise<void> {
    try {
      if (fs.existsSync(this.cacheFile)) {
        await fs.promises.unlink(this.cacheFile);
        console.error('[ToolCache] Cache invalidated');
      }
    } catch (error) {
      console.error('[ToolCache] Failed to invalidate cache:', error);
    }
  }
}
