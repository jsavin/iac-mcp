/**
 * App Tools Loader
 *
 * Orchestrates lazy loading of tools for a specific application.
 * Implements the cache-first loading strategy:
 *
 * 1. Check per-app cache for existing tools
 * 2. If cache valid → return cached tools (<100ms)
 * 3. If cache invalid/missing → parse SDEF and generate tools (1-3s)
 * 4. Save to cache for future requests
 * 5. Return tools and object model
 *
 * Phase 5 of lazy loading implementation.
 */

import { stat } from 'fs/promises';
import type { AppWithSDEF } from './find-sdef.js';
import type { SDEFDictionary } from '../../types/sdef.js';
import type { MCPTool } from '../../types/mcp-tool.js';
import type { AppToolsResponse } from '../../types/app-metadata.js';
import type { AppInfo } from '../../types/tool-generator.js';
import { SDEFParser } from './parse-sdef.js';
import { ToolGenerator } from '../tool-generator/generator.js';
import { PerAppCache, type PerAppCacheData } from '../cache/per-app-cache.js';
import { extractObjectModelSync } from './object-model-extractor.js';

/**
 * Error thrown when requested app is not found
 */
export class AppNotFoundError extends Error {
  constructor(appName: string) {
    super(`App "${appName}" not found in discovered apps`);
    this.name = 'AppNotFoundError';
  }
}

/**
 * Error thrown when SDEF file is not found
 */
export class SDEFNotFoundError extends Error {
  constructor(appName: string, sdefPath: string) {
    super(`SDEF file not found for app "${appName}" at: ${sdefPath}`);
    this.name = 'SDEFNotFoundError';
  }
}

/**
 * Error thrown when SDEF parsing fails
 */
export class SDEFParsingError extends Error {
  constructor(appName: string, cause: Error) {
    super(`Failed to parse SDEF for app "${appName}": ${cause.message}`);
    this.name = 'SDEFParsingError';
    this.cause = cause;
  }
}

/**
 * Error thrown when tool generation fails
 */
export class ToolGenerationError extends Error {
  constructor(appName: string, cause: Error) {
    super(`Failed to generate tools for app "${appName}": ${cause.message}`);
    this.name = 'ToolGenerationError';
    this.cause = cause;
  }
}

/**
 * Load tools for a specific application (lazy loading)
 *
 * Implements cache-first loading strategy with automatic cache invalidation.
 *
 * @param appName - Name of application to load tools for (case-insensitive)
 * @param discoveredApps - List of discovered apps with SDEF files
 * @param sdefParser - SDEF parser instance
 * @param toolGenerator - Tool generator instance
 * @param perAppCache - Per-app cache instance
 * @returns AppToolsResponse with tools and object model
 * @throws AppNotFoundError if app not found in discoveredApps
 * @throws SDEFNotFoundError if SDEF file not found
 * @throws SDEFParsingError if SDEF parsing fails
 * @throws ToolGenerationError if tool generation fails
 */
export async function loadAppTools(
  appName: string,
  discoveredApps: AppWithSDEF[],
  sdefParser: SDEFParser,
  toolGenerator: ToolGenerator,
  perAppCache: PerAppCache
): Promise<AppToolsResponse> {
  // Find app in discovered apps (case-insensitive)
  const app = discoveredApps.find(
    (a) => a.appName.toLowerCase() === appName.toLowerCase()
  );

  if (!app) {
    throw new AppNotFoundError(appName);
  }

  // Extract bundle ID from bundle path
  // Bundle ID convention: reverse domain from path component
  // e.g., /Applications/Safari.app → com.apple.Safari
  const bundleId = extractBundleId(app.bundlePath, app.appName);

  // Get modification times for cache validation
  let sdefMtime: number;
  let bundleMtime: number;

  try {
    const sdefStat = await stat(app.sdefPath);
    sdefMtime = sdefStat.mtimeMs;
  } catch (error) {
    throw new SDEFNotFoundError(appName, app.sdefPath);
  }

  try {
    const bundleStat = await stat(app.bundlePath);
    bundleMtime = bundleStat.mtimeMs;
  } catch (error) {
    // Bundle path error - treat as cache miss
    bundleMtime = Date.now();
  }

  // Check cache
  const isValid = await perAppCache.isValid(bundleId, sdefMtime, bundleMtime);

  if (isValid) {
    // Cache hit - load from cache
    const cached = await perAppCache.load(bundleId);
    if (cached) {
      // Extract object model from cached SDEF
      const objectModel = extractObjectModelSync(cached.parsedSDEF);

      return {
        appName: cached.appName,
        bundleId: cached.bundleId,
        tools: cached.generatedTools,
        objectModel,
      };
    }
  }

  // Cache miss or invalid - generate from SDEF
  let dictionary: SDEFDictionary;
  try {
    dictionary = await sdefParser.parse(app.sdefPath);
  } catch (error) {
    throw new SDEFParsingError(
      appName,
      error instanceof Error ? error : new Error(String(error))
    );
  }

  // Generate tools
  let tools: MCPTool[];
  try {
    const appInfo: AppInfo = {
      appName: app.appName,
      bundleId,
      bundlePath: app.bundlePath,
      sdefPath: app.sdefPath,
    };

    tools = toolGenerator.generateTools(dictionary, appInfo);
  } catch (error) {
    throw new ToolGenerationError(
      appName,
      error instanceof Error ? error : new Error(String(error))
    );
  }

  // Extract object model
  const objectModel = extractObjectModelSync(dictionary);

  // Save to cache
  try {
    const cacheData: PerAppCacheData = {
      appName: app.appName,
      bundleId,
      sdefPath: app.sdefPath,
      sdefModifiedTime: sdefMtime,
      bundleModifiedTime: bundleMtime,
      parsedSDEF: dictionary,
      generatedTools: tools,
      cachedAt: Date.now(),
    };

    await perAppCache.save(bundleId, cacheData);
  } catch (error) {
    // Cache save failure is not fatal - log warning and continue
    console.warn(
      `Warning: Failed to save cache for app "${appName}": ${
        error instanceof Error ? error.message : String(error)
      }`
    );
  }

  // Return response
  return {
    appName: app.appName,
    bundleId,
    tools,
    objectModel,
  };
}

/**
 * Extract bundle ID from bundle path and app name
 *
 * Attempts to extract bundle ID from Info.plist if available,
 * otherwise generates a conventional ID from the app name.
 *
 * @param bundlePath - Path to app bundle
 * @param appName - Application name
 * @returns Bundle identifier
 */
function extractBundleId(bundlePath: string, appName: string): string {
  // For now, use conventional naming
  // TODO: Read from Info.plist in future enhancement
  // System apps: com.apple.<name>
  // User apps: com.<vendor>.<name>

  if (bundlePath.startsWith('/System/') || bundlePath.startsWith('/Applications/')) {
    // Likely system app
    return `com.apple.${appName.toLowerCase().replace(/\s+/g, '')}`;
  }

  // User app - generate generic ID
  return `com.app.${appName.toLowerCase().replace(/\s+/g, '')}`;
}

/**
 * Invalidate cache for a specific app
 *
 * Forces regeneration of tools on next load.
 *
 * @param appName - Name of application
 * @param discoveredApps - List of discovered apps
 * @param perAppCache - Per-app cache instance
 * @throws AppNotFoundError if app not found
 */
export async function invalidateApp(
  appName: string,
  discoveredApps: AppWithSDEF[],
  perAppCache: PerAppCache
): Promise<void> {
  // Find app in discovered apps
  const app = discoveredApps.find(
    (a) => a.appName.toLowerCase() === appName.toLowerCase()
  );

  if (!app) {
    throw new AppNotFoundError(appName);
  }

  // Extract bundle ID
  const bundleId = extractBundleId(app.bundlePath, app.appName);

  // Invalidate cache
  await perAppCache.invalidate(bundleId);
}
