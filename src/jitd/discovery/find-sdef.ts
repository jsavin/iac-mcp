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

import { readdir, access, stat } from 'fs/promises';
import { constants } from 'fs';
import { join, basename, resolve, normalize } from 'path';
import { homedir } from 'os';

/**
 * Simple logger interface for error reporting
 */
export interface Logger {
  error(message: string, ...args: unknown[]): void;
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
 * Common directories where macOS applications are installed
 */
const COMMON_APP_DIRECTORIES = [
  '/System/Library/CoreServices',
  '/System/Applications',
  '/Applications',
  () => join(homedir(), 'Applications'), // User-specific apps
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

  return normalizedTarget.startsWith(normalizedBoundary);
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
 * Finds all scriptable applications (apps with SDEF files) on the system
 *
 * This function searches common application directories for .app bundles
 * and checks each one for an SDEF file. It handles:
 * - Multiple search directories
 * - Permission errors (skips inaccessible directories)
 * - Apps without SDEF files (filters them out)
 * - Caching for performance
 *
 * Common search locations:
 * - /System/Library/CoreServices
 * - /System/Applications
 * - /Applications
 * - ~/Applications
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

  // Search each common directory
  for (const dir of COMMON_APP_DIRECTORIES) {
    const directory = typeof dir === 'function' ? dir() : dir;

    try {
      const appBundles = await findAppBundles(directory, logger);

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

      // Filter out null results and add to discovered apps
      for (const result of sdefResults) {
        if (result) {
          discoveredApps.push(result);
        }
      }
    } catch (error) {
      // Log but continue with other directories
      logger.error(`Error processing directory ${directory}:`, error);
    }
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
