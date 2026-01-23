/**
 * SDEF File Discovery Module
 *
 * This module provides functions to discover SDEF (Scripting Definition) files
 * in macOS application bundles. SDEF files define the scriptable capabilities
 * of macOS applications.
 *
 * Key functions:
 * - findSDEFFile: Find SDEF file for a specific app bundle
 * - findAllScriptableApps: Discover all apps with SDEF files in common directories
 * - getSDEFPath: Construct expected SDEF path from app bundle path
 */

import { readdir, access, stat, realpath } from 'fs/promises';
import { constants } from 'fs';
import { join, basename, resolve, normalize } from 'path';
import { homedir } from 'os';

/**
 * Simple logger interface for error reporting
 */
export interface Logger {
  error(message: string, ...args: unknown[]): void;
  debug?(message: string, ...args: unknown[]): void;
}

/**
 * Default no-op logger (silent)
 */
const noOpLogger: Logger = {
  error: () => {}, // Silent by default
};

/**
 * Console logger for development/debugging
 */
export const consoleLogger: Logger = {
  error: console.error.bind(console),
  debug: console.debug.bind(console),
};

/**
 * Interface representing an application with an SDEF file
 */
export interface AppWithSDEF {
  appName: string;
  bundlePath: string;
  sdefPath: string;
}

/**
 * Cache for discovered SDEF files to improve performance
 */
interface SDEFCache {
  timestamp: number;
  apps: AppWithSDEF[];
}

let sdefCache: SDEFCache | null = null;
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

/**
 * Directories to search recursively for applications (limited depth)
 */
const RECURSIVE_SEARCH_DIRECTORIES = [
  '/System/Applications',
  '/Applications',
  () => join(homedir(), 'Applications'),
];

/**
 * Directories to search non-recursively (top-level only)
 * These are known to potentially contain apps but recursing would be too expensive
 */
const TOP_LEVEL_ONLY_DIRECTORIES = [
  () => join(homedir(), 'Library', 'PreferencePanes'),
  () => join(homedir(), 'Library', 'Screen Savers'),
];

/**
 * Validates that the input path is safe and well-formed
 *
 * @param path - Path to validate
 * @throws Error if path is invalid
 */
function validatePath(path: string): void {
  if (!path || typeof path !== 'string' || path.trim() === '') {
    throw new Error('Invalid path: path must be a non-empty string');
  }
}

/**
 * Checks if a file exists and is readable
 *
 * @param filePath - Path to check
 * @returns true if file exists and is readable, false otherwise
 */
async function isReadableFile(filePath: string): Promise<boolean> {
  try {
    await access(filePath, constants.R_OK);
    const stats = await stat(filePath);
    return stats.isFile();
  } catch (error) {
    return false;
  }
}

/**
 * Checks if a directory exists and is readable
 *
 * @param dirPath - Directory path to check
 * @returns true if directory exists and is readable, false otherwise
 */
async function isReadableDirectory(dirPath: string): Promise<boolean> {
  try {
    await access(dirPath, constants.R_OK);
    const stats = await stat(dirPath);
    return stats.isDirectory();
  } catch (error) {
    return false;
  }
}

/**
 * Validates that a path is within the expected boundary directory
 * Prevents path traversal attacks by ensuring resolved path stays within bounds
 *
 * @param targetPath - The path to validate
 * @param boundaryPath - The directory that should contain the target
 * @returns true if target is within boundary, false otherwise
 */
function isPathWithinBoundary(targetPath: string, boundaryPath: string): boolean {
  const normalizedTarget = normalize(resolve(targetPath));
  const normalizedBoundary = normalize(resolve(boundaryPath));

  // Ensure boundary ends with separator for exact directory match
  // This prevents '/Applications' from matching '/ApplicationsMalicious/'
  const boundaryWithSep = normalizedBoundary.endsWith('/')
    ? normalizedBoundary
    : normalizedBoundary + '/';

  return normalizedTarget === normalizedBoundary ||
         normalizedTarget.startsWith(boundaryWithSep);
}

/**
 * Constructs the expected SDEF file path from an app bundle path
 *
 * macOS app bundles typically have the structure:
 * AppName.app/Contents/Resources/AppName.sdef
 *
 * @param appBundlePath - Path to the .app bundle
 * @returns Expected path to SDEF file
 */
export function getSDEFPath(appBundlePath: string): string {
  validatePath(appBundlePath);

  const appName = basename(appBundlePath, '.app');
  return join(appBundlePath, 'Contents', 'Resources', `${appName}.sdef`);
}

/**
 * Finds the SDEF file for a given application bundle
 *
 * This function looks for an SDEF file in the standard location within
 * an app bundle (Contents/Resources/*.sdef). It handles various error
 * cases gracefully:
 * - App bundle doesn't exist
 * - App bundle exists but has no SDEF file
 * - Permission denied
 * - Malformed app bundle structure
 *
 * @param appBundlePath - Absolute path to the .app bundle (e.g., '/Applications/Safari.app')
 * @param logger - Optional logger for error reporting (default: silent)
 * @returns Path to SDEF file if found, null otherwise
 * @throws Error if path is invalid (null, undefined, empty string)
 */
export async function findSDEFFile(
  appBundlePath: string,
  logger: Logger = noOpLogger
): Promise<string | null> {
  validatePath(appBundlePath);

  // Check if the app bundle exists and is a directory
  if (!(await isReadableDirectory(appBundlePath))) {
    return null;
  }

  // Check if Contents directory exists
  const contentsPath = join(appBundlePath, 'Contents');
  if (!(await isReadableDirectory(contentsPath))) {
    return null;
  }

  // Check if Resources directory exists
  const resourcesPath = join(contentsPath, 'Resources');
  if (!(await isReadableDirectory(resourcesPath))) {
    return null;
  }

  try {
    // First, try the standard naming convention: AppName.sdef
    const expectedSDEFPath = getSDEFPath(appBundlePath);
    if (await isReadableFile(expectedSDEFPath)) {
      return expectedSDEFPath;
    }

    // If standard path doesn't work, search for any .sdef file in Resources
    const files = await readdir(resourcesPath);
    const sdefFiles = files.filter((file) => file.endsWith('.sdef'));

    if (sdefFiles.length === 0) {
      return null;
    }

    // Return the first SDEF file found
    const firstSdefFile = sdefFiles[0];
    if (!firstSdefFile) {
      return null;
    }
    const sdefPath = join(resourcesPath, firstSdefFile);

    // Security: Verify path is within expected boundary (prevent path traversal)
    if (!isPathWithinBoundary(sdefPath, resourcesPath)) {
      logger.error(`Path traversal attempt detected: ${firstSdefFile}`);
      return null;
    }

    // Verify it's readable before returning
    if (await isReadableFile(sdefPath)) {
      return sdefPath;
    }

    return null;
  } catch (error) {
    // Log error but don't crash
    logger.error(`Error finding SDEF file in ${appBundlePath}:`, error);
    return null;
  }
}

/**
 * Scans a directory for .app bundles
 *
 * @param directory - Directory to scan
 * @param logger - Optional logger for error reporting
 * @returns Array of absolute paths to .app bundles
 */
async function findAppBundles(directory: string, logger: Logger = noOpLogger): Promise<string[]> {
  try {
    // Check if directory is readable
    if (!(await isReadableDirectory(directory))) {
      return [];
    }

    const entries = await readdir(directory);
    const appBundles: string[] = [];

    for (const entry of entries) {
      if (entry.endsWith('.app')) {
        const fullPath = join(directory, entry);

        // Security: Verify path is within expected boundary (prevent path traversal)
        if (!isPathWithinBoundary(fullPath, directory)) {
          logger.error(`Path traversal attempt detected in app discovery: ${entry}`);
          continue;
        }

        // Verify it's actually a directory (app bundle)
        if (await isReadableDirectory(fullPath)) {
          appBundles.push(fullPath);
        }
      }
    }

    return appBundles;
  } catch (error) {
    // Log error but continue with other directories
    logger.error(`Error scanning directory ${directory}:`, error);
    return [];
  }
}

/**
 * Tracks visited paths to prevent infinite loops from circular symlinks
 */
interface VisitedPaths {
  paths: Set<string>;
}

/**
 * Tracks statistics about permission errors during discovery
 */
interface PermissionErrorStats {
  count: number;
}

/**
 * Directories that should be skipped during recursive search
 * These are known to not contain .app bundles or are too large/deep
 */
const SKIP_DIRECTORIES = new Set([
  '.git',
  'node_modules',
  '.npm',
  '.cache',
  'Cache',
  'Caches',
  'Frameworks',
  'Resources',
  'Contents', // Inside .app bundles
  'Logs',
  'tmp',
  'temp',
  '.Trash',
  'Trash',
]);

/**
 * Recursively scans a directory and its subdirectories for .app bundles
 *
 * This function searches through all subdirectories to find application bundles
 * that might be nested in folder hierarchies. It handles:
 * - Circular symlinks (tracks visited paths to prevent infinite loops)
 * - Permission errors (logs and continues)
 * - Deep nesting (handles gracefully)
 * - .localized directory names
 *
 * @param directory - Directory to scan recursively
 * @param logger - Optional logger for error reporting
 * @param visited - Tracks visited paths to prevent infinite loops
 * @param depth - Current recursion depth (for safety limits)
 * @param maxDepth - Maximum recursion depth (default: 5)
 * @returns Array of absolute paths to .app bundles
 */
async function findAppBundlesRecursive(
  directory: string,
  logger: Logger = noOpLogger,
  visited: VisitedPaths = { paths: new Set() },
  depth: number = 0,
  maxDepth: number = 5,
  permissionErrorStats: PermissionErrorStats = { count: 0 }
): Promise<string[]> {
  // Safety: Prevent excessive recursion
  if (depth > maxDepth) {
    return [];
  }

  try {
    // Check if directory is readable
    if (!(await isReadableDirectory(directory))) {
      return [];
    }

    // Get real path to handle symlinks
    const realPath = await import('fs/promises').then(fs => fs.realpath(directory).catch(() => directory));

    // Check for circular symlinks
    if (visited.paths.has(realPath)) {
      return [];
    }

    // Mark this path as visited
    visited.paths.add(realPath);

    const entries = await readdir(directory);
    const appBundles: string[] = [];

    for (const entry of entries) {
      const fullPath = join(directory, entry);

      // Security: Verify path is within expected boundary
      if (!isPathWithinBoundary(fullPath, directory)) {
        logger.error(`Path traversal attempt detected in recursive search: ${entry}`);
        continue;
      }

      try {
        // Check if it's an app bundle
        if (entry.endsWith('.app')) {
          // Verify it's actually a directory (app bundle)
          if (await isReadableDirectory(fullPath)) {
            appBundles.push(fullPath);
            // Don't recurse into .app bundles
          }
        } else {
          // Skip directories that are known to not contain apps
          if (SKIP_DIRECTORIES.has(entry)) {
            continue;
          }

          // If it's a regular directory (not .app), recurse into it
          const stats = await stat(fullPath);
          if (stats.isDirectory()) {
            const nestedApps = await findAppBundlesRecursive(
              fullPath,
              logger,
              visited,
              depth + 1,
              maxDepth,
              permissionErrorStats
            );
            appBundles.push(...nestedApps);
          }
        }
      } catch (error) {
        // Item 2: Add debug-level logging for suppressed permission errors
        // Track permission errors for observability without spamming logs
        permissionErrorStats.count++;

        // Only log if debug logging is enabled
        if (logger.debug) {
          const errorMessage = error instanceof Error ? error.message : String(error);
          logger.debug(`Permission error #${permissionErrorStats.count} in ${fullPath}: ${errorMessage}`);
        }
        continue;
      }
    }

    return appBundles;
  } catch (error) {
    // Log error but continue with other directories
    logger.error(`Error in recursive search of ${directory}:`, error);
    return [];
  }
}

/**
 * Processes app bundles to find those with SDEF files
 *
 * @param appBundles - Array of app bundle paths to process
 * @param logger - Optional logger for error reporting
 * @param seenPaths - Set of already processed paths to avoid duplicates
 * @param discoveredApps - Array to add discovered apps to
 */
async function processAppBundles(
  appBundles: string[],
  logger: Logger,
  seenPaths: Set<string>,
  discoveredApps: AppWithSDEF[]
): Promise<void> {
  // Check each app bundle for SDEF file (parallelized for performance)
  const sdefResults = await Promise.all(
    appBundles.map(async (bundlePath) => {
      const sdefPath = await findSDEFFile(bundlePath, logger);
      if (sdefPath) {
        return {
          appName: basename(bundlePath, '.app'),
          bundlePath,
          sdefPath,
        };
      }
      return null;
    })
  );

  // Filter out null results and add to discovered apps (avoiding duplicates)
  for (const result of sdefResults) {
    if (result) {
      // Item 4: Normalize paths to catch duplicates with different representations (symlinks, etc.)
      const normalizedPath = await realpath(result.bundlePath).catch(() => result.bundlePath);
      if (!seenPaths.has(normalizedPath)) {
        seenPaths.add(normalizedPath);
        discoveredApps.push(result);
      }
    }
  }
}

/**
 * Finds all scriptable applications (apps with SDEF files) on the system
 *
 * This function searches common application directories for .app bundles
 * and checks each one for an SDEF file. It handles:
 * - Multiple search directories (both top-level and recursive)
 * - Permission errors (skips inaccessible directories)
 * - Apps without SDEF files (filters them out)
 * - Caching for performance
 * - Circular symlinks (prevents infinite loops)
 * - Deep nesting (handles gracefully)
 *
 * Common search locations:
 * - /System/Library/CoreServices (top-level only)
 * - /System/Applications (recursive)
 * - /Applications (recursive)
 * - ~/Applications (recursive)
 * - ~/Library/Application Support (recursive)
 * - ~/Library/PreferencePanes (recursive)
 * - ~/Library/Screen Savers (recursive)
 *
 * @param options - Optional configuration
 * @param options.useCache - Whether to use cached results (default: true)
 * @param options.logger - Optional logger for error reporting (default: silent)
 * @returns Array of applications with SDEF files
 */
export async function findAllScriptableApps(
  options: { useCache?: boolean; logger?: Logger } = {}
): Promise<AppWithSDEF[]> {
  const { useCache = true, logger = noOpLogger } = options;

  // Check cache first
  if (useCache && sdefCache) {
    const age = Date.now() - sdefCache.timestamp;
    if (age < CACHE_TTL_MS) {
      // Return shallow copy to prevent mutation of cached array
      return [...sdefCache.apps];
    }
  }

  const discoveredApps: AppWithSDEF[] = [];
  const seenPaths = new Set<string>(); // Track seen paths to prevent duplicates

  // Search /System/Library/CoreServices (non-recursive, as it's a flat directory)
  try {
    const directory = '/System/Library/CoreServices';
    const appBundles = await findAppBundles(directory, logger);
    await processAppBundles(appBundles, logger, seenPaths, discoveredApps);
  } catch (error) {
    logger.error('Error processing /System/Library/CoreServices:', error);
  }

  // Search recursive directories
  for (const dir of RECURSIVE_SEARCH_DIRECTORIES) {
    const directory = typeof dir === 'function' ? dir() : dir;

    try {
      const appBundles = await findAppBundlesRecursive(directory, logger);
      await processAppBundles(appBundles, logger, seenPaths, discoveredApps);
    } catch (error) {
      // Log but continue with other directories
      logger.error(`Error processing directory ${directory}:`, error);
    }
  }

  // Search top-level only directories (no recursion to avoid performance issues)
  for (const dir of TOP_LEVEL_ONLY_DIRECTORIES) {
    const directory = typeof dir === 'function' ? dir() : dir;

    try {
      const appBundles = await findAppBundles(directory, logger);
      await processAppBundles(appBundles, logger, seenPaths, discoveredApps);
    } catch (error) {
      logger.error(`Error processing top-level directory ${directory}:`, error);
    }
  }

  // Search ~/Library/Application Support with limited recursion (only 1 level deep)
  // This is necessary to find apps in subdirectories like Chrome Apps
  try {
    const libraryAppSupport = join(homedir(), 'Library', 'Application Support');
    if (await isReadableDirectory(libraryAppSupport)) {
      const subdirs = await readdir(libraryAppSupport);

      for (const subdir of subdirs) {
        const subdirPath = join(libraryAppSupport, subdir);

        try {
          // Only check subdirectories that might contain apps
          if (await isReadableDirectory(subdirPath)) {
            const appBundles = await findAppBundles(subdirPath, logger);
            await processAppBundles(appBundles, logger, seenPaths, discoveredApps);
          }
        } catch (error) {
          // Skip inaccessible subdirectories
          continue;
        }
      }
    }
  } catch (error) {
    logger.error('Error processing ~/Library/Application Support:', error);
  }

  // Update cache
  sdefCache = {
    timestamp: Date.now(),
    apps: discoveredApps,
  };

  return discoveredApps;
}

/**
 * Invalidates the SDEF cache, forcing a fresh scan on next discovery
 *
 * This is useful when:
 * - New applications are installed
 * - Applications are updated
 * - You want to ensure you have the latest information
 */
export function invalidateCache(): void {
  sdefCache = null;
}

/**
 * Validates that a file appears to be an SDEF file (basic XML check)
 *
 * This is a simple validation that checks if the file starts with XML
 * declaration. Full XML parsing is done by the SDEF parser module.
 *
 * @param filePath - Path to potential SDEF file
 * @param logger - Optional logger for error reporting (default: silent)
 * @returns true if file appears to be XML, false otherwise
 */
export async function isValidSDEFFile(
  filePath: string,
  logger: Logger = noOpLogger
): Promise<boolean> {
  try {
    validatePath(filePath);

    if (!(await isReadableFile(filePath))) {
      return false;
    }

    // Read first few bytes to check for XML declaration
    const fs = await import('fs/promises');
    const handle = await fs.open(filePath, 'r');

    try {
      const buffer = Buffer.alloc(100);
      await handle.read(buffer, 0, 100, 0);
      const content = buffer.toString('utf8');

      // Check for XML declaration or dictionary tag
      return (
        content.includes('<?xml') ||
        content.includes('<dictionary') ||
        content.includes('<suite')
      );
    } finally {
      await handle.close();
    }
  } catch (error) {
    logger.error(`Error validating SDEF file ${filePath}:`, error);
    return false;
  }
}

/**
 * Gets information about common scriptable macOS apps
 *
 * This provides a quick list of well-known scriptable apps to test against.
 *
 * @returns Array of paths to known scriptable apps
 */
export function getKnownScriptableApps(): string[] {
  return [
    '/System/Library/CoreServices/Finder.app',
    '/System/Applications/Mail.app',
    '/System/Applications/Safari.app',
    '/System/Applications/Calendar.app',
    '/System/Applications/Contacts.app',
    '/System/Applications/Notes.app',
    '/System/Applications/Reminders.app',
    '/System/Applications/Music.app',
    '/System/Applications/Photos.app',
  ];
}
