/**
 * Type Schema Cache
 *
 * Provides caching for parsed SDEF classes and generated TypeScript type definitions.
 * Supports lazy loading and automatic invalidation when SDEF files change.
 *
 * Cache Structure:
 * - Key: Bundle ID
 * - Value: TypeSchemaCache (classes, enumerations, TypeScript code, lastParsed)
 *
 * Invalidation:
 * - Checks SDEF file mtime against lastParsed timestamp
 * - Re-parses if SDEF file is modified
 */

import { stat } from 'fs/promises';
import { readFile } from 'fs/promises';
import { parseSDEFClasses } from '../discovery/class-parser.js';
import { generateTypeScriptTypes } from '../type-generator/type-generator.js';
import type { ParsedClass, ParsedEnumeration } from '../discovery/types.js';
import type { ClassInfo, EnumerationInfo } from '../../types/app-metadata.js';

/**
 * Cached type schema for an application
 */
export interface TypeSchemaCache {
  /**
   * Parsed classes from SDEF
   */
  classes: ParsedClass[];

  /**
   * Parsed enumerations from SDEF
   */
  enumerations: ParsedEnumeration[];

  /**
   * Generated TypeScript code
   */
  typescriptCode: string;

  /**
   * Timestamp when SDEF was last parsed
   */
  lastParsed: Date;
}

/**
 * Manager for type schema caching
 *
 * Maintains in-memory cache of parsed SDEF classes and generated types.
 * Automatically invalidates stale cache entries based on SDEF file mtime.
 */
export class TypeSchemaCacheManager {
  /**
   * In-memory cache: bundleId -> TypeSchemaCache
   */
  private cache: Map<string, TypeSchemaCache>;

  constructor() {
    this.cache = new Map();
  }

  /**
   * Get or parse type schema for an application
   *
   * Returns cached schema if available and up-to-date,
   * otherwise parses SDEF and caches result.
   *
   * @param bundleId - Application bundle identifier
   * @param sdefPath - Path to SDEF file
   * @returns Type schema cache
   * @throws Error if SDEF file is not readable or parsing fails
   */
  async getOrParse(
    bundleId: string,
    sdefPath: string
  ): Promise<TypeSchemaCache> {
    // Check if we have cached data
    const cached = this.cache.get(bundleId);

    if (cached) {
      // Check if cache is stale
      const isStale = await this.isStale(sdefPath, cached.lastParsed);

      if (!isStale) {
        // Cache is still valid
        return cached;
      }

      // Cache is stale, need to re-parse
      console.error(`[TypeSchemaCache] Cache stale for ${bundleId}, re-parsing`);
    }

    // Parse SDEF and generate types
    console.error(`[TypeSchemaCache] Parsing SDEF for ${bundleId}`);
    const schema = await this.parseAndGenerate(sdefPath);

    // Cache the result
    this.cache.set(bundleId, schema);

    return schema;
  }

  /**
   * Parse SDEF file and generate TypeScript types
   *
   * @param sdefPath - Path to SDEF file
   * @returns Type schema cache
   * @throws Error if SDEF file is not readable or parsing fails
   */
  private async parseAndGenerate(sdefPath: string): Promise<TypeSchemaCache> {
    // Read SDEF file
    const sdefXML = await readFile(sdefPath, 'utf-8');

    // Parse classes and enumerations
    const { classes, enumerations } = parseSDEFClasses(sdefXML);

    // Convert to ClassInfo/EnumerationInfo format for type generator
    const classInfos: ClassInfo[] = classes.map(c => ({
      name: c.name,
      code: c.code,
      inherits: c.inherits,
      description: c.description || '',
      properties: c.properties.map(p => ({
        name: p.name,
        code: p.code,
        type: Array.isArray(p.type) ? p.type.join(' | ') : p.type,
        description: p.description || '',
      })),
      elements: c.elements.map(e => ({
        name: e.type,
        type: e.type,
        description: '',
      })),
    }));

    const enumInfos: EnumerationInfo[] = enumerations.map(e => ({
      name: e.name,
      code: e.code,
      description: '',
      values: e.enumerators.map(v => ({
        name: v.name,
        code: v.code,
        description: v.description || '',
      })),
    }));

    // Generate TypeScript code
    const typescriptCode = generateTypeScriptTypes(classInfos, enumInfos);

    return {
      classes,
      enumerations,
      typescriptCode,
      lastParsed: new Date(),
    };
  }

  /**
   * Check if SDEF file has been modified since last parse
   *
   * @param sdefPath - Path to SDEF file
   * @param lastParsed - Timestamp when SDEF was last parsed
   * @returns true if SDEF file is modified after lastParsed
   */
  private async isStale(sdefPath: string, lastParsed: Date): Promise<boolean> {
    try {
      const stats = await stat(sdefPath);
      const sdefMtime = stats.mtime;

      // Compare modification times
      return sdefMtime > lastParsed;
    } catch (error) {
      // If we can't stat the file, assume cache is stale
      console.error(`[TypeSchemaCache] Error checking SDEF mtime: ${error}`);
      return true;
    }
  }

  /**
   * Clear cache for a specific bundle ID or all entries
   *
   * @param bundleId - Optional bundle ID to clear (clears all if omitted)
   */
  clear(bundleId?: string): void {
    if (bundleId) {
      this.cache.delete(bundleId);
      console.error(`[TypeSchemaCache] Cleared cache for ${bundleId}`);
    } else {
      this.cache.clear();
      console.error(`[TypeSchemaCache] Cleared all cache entries`);
    }
  }

  /**
   * Get cache statistics
   *
   * @returns Number of cached entries
   */
  size(): number {
    return this.cache.size;
  }
}
