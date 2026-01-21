/**
 * SDEF Test Helpers
 *
 * Shared utilities for testing SDEF parsing and validation.
 * Eliminates code duplication in integration tests per CODE-QUALITY.md standards.
 */

import { findSDEFFile } from '../../src/jitd/discovery/find-sdef.js';
import { SDEFParser } from '../../src/jitd/discovery/parse-sdef.js';
import type { SDEFDictionary } from '../../src/types/sdef.js';

/**
 * Result of SDEF test setup
 */
export interface SDEFTestContext {
  sdefPath: string;
  dictionary: SDEFDictionary;
  allCommands: string[];
}

/**
 * Setup SDEF test context for an app
 *
 * Finds SDEF file, parses it, and extracts commands.
 * Returns null if SDEF file not found or parsing fails.
 *
 * This eliminates duplicated setup logic across multiple test suites.
 *
 * @param bundlePath - Path to the app bundle (e.g., /Applications/Pages.app)
 * @returns Test context with parsed dictionary and commands, or null if unavailable
 *
 * @example
 * ```typescript
 * let testContext: SDEFTestContext | null;
 *
 * beforeAll(async () => {
 *   testContext = await setupSDEFTest('/Applications/Pages.app');
 * });
 *
 * it('should parse successfully', () => {
 *   if (!testContext) return; // Skip if setup failed
 *   expect(testContext.dictionary).toBeTruthy();
 * });
 * ```
 */
export async function setupSDEFTest(
  bundlePath: string
): Promise<SDEFTestContext | null> {
  // Find SDEF file
  const sdefPath = await findSDEFFile(bundlePath);
  if (!sdefPath) {
    return null;
  }

  // Parse SDEF
  const parser = new SDEFParser();
  let dictionary: SDEFDictionary;
  try {
    dictionary = await parser.parse(sdefPath);
  } catch (error) {
    // Parsing failed - return null to signal tests should skip
    return null;
  }

  // Extract all commands from all suites
  const allCommands: string[] = [];
  for (const suite of dictionary.suites) {
    for (const cmd of suite.commands) {
      allCommands.push(cmd.name);
    }
  }

  return {
    sdefPath,
    dictionary,
    allCommands,
  };
}

/**
 * Check if any types in the dictionary are "unknown"
 *
 * Used to verify that XInclude resolution and type inference work correctly.
 * If types are "unknown", it indicates incomplete parsing or missing type definitions.
 *
 * @param dictionary - Parsed SDEF dictionary
 * @returns true if any "unknown" types found, false otherwise
 *
 * @example
 * ```typescript
 * const hasUnknown = hasUnknownTypes(testContext.dictionary);
 * expect(hasUnknown).toBe(false); // All types should be resolved
 * ```
 */
export function hasUnknownTypes(dictionary: SDEFDictionary): boolean {
  for (const suite of dictionary.suites) {
    for (const cmd of suite.commands) {
      // Check parameters
      for (const param of cmd.parameters) {
        if (param.type.kind === 'primitive' && param.type.type === 'unknown') {
          return true;
        }
      }
      // Check result
      if (
        cmd.result &&
        cmd.result.kind === 'primitive' &&
        cmd.result.type === 'unknown'
      ) {
        return true;
      }
      // Check direct parameter
      if (
        cmd.directParameter &&
        cmd.directParameter.type.kind === 'primitive' &&
        cmd.directParameter.type.type === 'unknown'
      ) {
        return true;
      }
    }

    // Check classes
    for (const cls of suite.classes) {
      for (const prop of cls.properties) {
        if (prop.type.kind === 'primitive' && prop.type.type === 'unknown') {
          return true;
        }
      }
    }
  }
  return false;
}

/**
 * Extract all command names from a dictionary
 *
 * Flattens commands from all suites into a single array.
 *
 * @param dictionary - Parsed SDEF dictionary
 * @returns Array of command names
 *
 * @example
 * ```typescript
 * const allCommands = getAllCommands(testContext.dictionary);
 * expect(allCommands).toContain('get');
 * expect(allCommands).toContain('set');
 * expect(allCommands.length).toBeGreaterThan(10);
 * ```
 */
export function getAllCommands(dictionary: SDEFDictionary): string[] {
  const commands: string[] = [];
  for (const suite of dictionary.suites) {
    for (const cmd of suite.commands) {
      commands.push(cmd.name);
    }
  }
  return commands;
}
