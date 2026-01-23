/**
 * App Metadata Builder
 *
 * Builds lightweight AppMetadata from AppWithSDEF and SDEF dictionary
 * WITHOUT generating full tool definitions.
 *
 * This is used for fast list_apps responses that show available apps
 * without the overhead of tool generation.
 *
 * Phase 3 of lazy loading implementation.
 */

import type { AppWithSDEF } from './find-sdef.js';
import type { SDEFDictionary } from '../../types/sdef.js';
import type { AppMetadata } from '../../types/app-metadata.js';

/**
 * Infers bundle ID from app bundle path
 *
 * Attempts to extract bundle ID from the app's bundle path.
 * For system apps, follows Apple naming conventions.
 * For third-party apps, creates a reasonable default.
 *
 * @param appName - Application name (e.g., "Finder")
 * @param bundlePath - Path to app bundle (e.g., "/Applications/Safari.app")
 * @returns Inferred bundle identifier
 */
function inferBundleId(appName: string, bundlePath: string): string {
  // Check if it's a system app
  if (bundlePath.startsWith('/System/')) {
    // System apps typically use com.apple.* bundle IDs
    return `com.apple.${appName.toLowerCase().replace(/\s+/g, '')}`;
  }

  // For third-party apps in /Applications, use a generic pattern
  // In production, this would read the Info.plist, but for now use convention
  return `com.app.${appName.toLowerCase().replace(/\s+/g, '')}`;
}

/**
 * Counts total commands across all suites
 *
 * @param dictionary - Parsed SDEF dictionary
 * @returns Total number of commands
 */
function countTotalCommands(dictionary: SDEFDictionary): number {
  return dictionary.suites.reduce((total, suite) => {
    return total + suite.commands.length;
  }, 0);
}

/**
 * Extracts suite names in order
 *
 * @param dictionary - Parsed SDEF dictionary
 * @returns Array of suite names
 */
function extractSuiteNames(dictionary: SDEFDictionary): string[] {
  return dictionary.suites.map((suite) => suite.name);
}

/**
 * Generates description from SDEF dictionary
 *
 * Uses dictionary title or first suite description.
 *
 * @param dictionary - Parsed SDEF dictionary
 * @returns Description string
 */
function generateDescription(dictionary: SDEFDictionary): string {
  // Prefer dictionary title
  if (dictionary.title) {
    return dictionary.title;
  }

  // Fallback to first suite description
  if (dictionary.suites.length > 0 && dictionary.suites[0]?.description) {
    return dictionary.suites[0].description;
  }

  // Final fallback
  return 'Scriptable application';
}

/**
 * Builds lightweight app metadata from AppWithSDEF and SDEF dictionary
 *
 * Extracts metadata WITHOUT generating full tool definitions:
 * - App name
 * - Bundle ID (inferred from bundle path or read from SDEF)
 * - Description (from SDEF title or first suite)
 * - Tool count (total commands across all suites)
 * - Suite names (list of suite names in order)
 *
 * Performance: Should complete in <30ms per app
 *
 * @param app - Application with SDEF file information
 * @param dictionary - Parsed SDEF dictionary
 * @returns AppMetadata object
 */
export async function buildMetadata(
  app: AppWithSDEF,
  dictionary: SDEFDictionary
): Promise<AppMetadata> {
  return {
    appName: app.appName,
    bundleId: inferBundleId(app.appName, app.bundlePath),
    description: generateDescription(dictionary),
    toolCount: countTotalCommands(dictionary),
    suiteNames: extractSuiteNames(dictionary),
    parsingStatus: {
      status: 'success',
    },
  };
}

/**
 * Builds metadata for multiple apps in batch
 *
 * Processes multiple apps and their SDEF dictionaries in parallel
 * for better performance.
 *
 * @param apps - Array of app and dictionary pairs
 * @returns Array of AppMetadata objects in same order as input
 */
export async function buildMetadataBatch(
  apps: Array<{ app: AppWithSDEF; dictionary: SDEFDictionary }>
): Promise<AppMetadata[]> {
  // Process all apps in parallel
  const metadataPromises = apps.map(({ app, dictionary }) =>
    buildMetadata(app, dictionary)
  );

  return Promise.all(metadataPromises);
}

/**
 * Synchronous version of buildMetadata for performance-critical paths
 *
 * @param app - Application with SDEF file information
 * @param dictionary - Parsed SDEF dictionary
 * @returns AppMetadata object
 */
export function buildMetadataSync(
  app: AppWithSDEF,
  dictionary: SDEFDictionary
): AppMetadata {
  return {
    appName: app.appName,
    bundleId: inferBundleId(app.appName, app.bundlePath),
    description: generateDescription(dictionary),
    toolCount: countTotalCommands(dictionary),
    suiteNames: extractSuiteNames(dictionary),
    parsingStatus: {
      status: 'success',
    },
  };
}

/**
 * Sanitizes error messages to prevent information leakage
 *
 * Removes sensitive information from error messages:
 * - File system paths (absolute paths, user directories)
 * - Stack traces (only keeps first line)
 * - Long messages (truncates to max 200 chars)
 *
 * Maps common error patterns to generic messages for security.
 *
 * @param error - Error object or unknown error
 * @returns Sanitized error message safe for external exposure
 */
function sanitizeErrorMessage(error: Error | unknown): string {
  const message = error instanceof Error ? error.message : String(error);

  // Remove absolute file paths (any string starting with /)
  let sanitized = message.replace(/\/[^\s]+/g, '<file path>');

  // Remove Windows paths (C:\...)
  sanitized = sanitized.replace(/[A-Z]:\\[^\s]+/g, '<file path>');

  // Remove user home directory references
  sanitized = sanitized.replace(/~\/[^\s]+/g, '<file path>');

  // Take only first line (removes stack traces)
  sanitized = sanitized.split('\n')[0] || sanitized;

  // Truncate if too long (max 200 chars)
  if (sanitized.length > 200) {
    sanitized = sanitized.substring(0, 197) + '...';
  }

  // Generic message for common cases
  if (sanitized.toLowerCase().includes('enoent')) {
    return 'SDEF file not found or inaccessible';
  }
  if (sanitized.toLowerCase().includes('permission denied')) {
    return 'Permission denied reading SDEF file';
  }
  if (sanitized.toLowerCase().includes('parse') || sanitized.toLowerCase().includes('xml')) {
    return 'XML parsing error in SDEF file';
  }

  return sanitized;
}

/**
 * Builds fallback metadata for apps with unparseable SDEF files
 *
 * When SDEF parsing completely fails (XML errors, missing files, etc.),
 * this function creates basic metadata with status 'failed' rather than
 * hiding the app completely.
 *
 * @param app - Application with SDEF file information
 * @param error - Error that occurred during SDEF parsing
 * @returns AppMetadata object with failed status
 */
export function buildFallbackMetadata(
  app: AppWithSDEF,
  error: Error
): AppMetadata {
  return {
    appName: app.appName,
    bundleId: inferBundleId(app.appName, app.bundlePath),
    description: 'Unable to parse SDEF file',
    toolCount: 0,
    suiteNames: [],
    parsingStatus: {
      status: 'failed',
      errorMessage: sanitizeErrorMessage(error),
    },
  };
}
