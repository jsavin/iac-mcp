/**
 * Type Mapper for SDEF to TypeScript Type Conversion
 *
 * Maps AppleScript/SDEF types to TypeScript types.
 */

import { toPascalCase } from './naming.js';

/**
 * Map of SDEF primitive types to TypeScript types
 *
 * Handles all common SDEF types including:
 * - Primitives: text, integer, boolean, etc.
 * - Special types: file, date, record
 * - AppleScript-specific: specifier, missing value
 */
export const SDEF_TO_TS_TYPE_MAP: Record<string, string> = {
  text: 'string',
  integer: 'number',
  real: 'number',
  'double integer': 'number',
  boolean: 'boolean',
  date: 'Date',
  file: 'string',
  alias: 'string',
  specifier: 'any',
  reference: 'any',
  'RGB color': '[number, number, number]',
  'bounding rectangle': '[number, number, number, number]',
  'missing value': 'null',
  record: 'Record<string, any>',
  list: 'Array<unknown>',
  any: 'any',
  type: 'string',
  color: 'string',
  property: 'string',
  'location specifier': 'string',
  'save options': 'SaveOptions',
};

/**
 * Map SDEF type to TypeScript type
 *
 * Handles:
 * - Primitive types (text → string, integer → number)
 * - List types (text with list=true → string[])
 * - Union types (['text', 'missing value'] → string | null)
 * - Custom types (window → Window, save options → SaveOptions)
 * - "list of X" string format → X[]
 * - "X or Y" string format → X | Y
 *
 * @param sdefType - SDEF type string or array of types for unions
 * @param list - Whether this is a list type (for wrapping in array)
 * @returns TypeScript type string
 *
 * @example
 * mapSDEFTypeToTypeScript('text') // 'string'
 * mapSDEFTypeToTypeScript('text', true) // 'string[]'
 * mapSDEFTypeToTypeScript('list of text') // 'string[]'
 * mapSDEFTypeToTypeScript(['text', 'missing value']) // 'string | null'
 * mapSDEFTypeToTypeScript('window') // 'Window'
 */
export function mapSDEFTypeToTypeScript(
  sdefType: string | string[],
  list: boolean = false
): string {
  // Handle union types (array of types)
  if (Array.isArray(sdefType)) {
    const mappedTypes = sdefType.map((t) => mapSDEFTypeToTypeScript(t.trim()));
    return mappedTypes.join(' | ');
  }

  // Normalize type string
  const normalized = sdefType.trim();

  // Handle "list of X" format
  if (normalized.startsWith('list of ')) {
    const itemType = normalized.substring('list of '.length).trim();
    const mappedItemType = mapSDEFTypeToTypeScript(itemType);
    return `${mappedItemType}[]`;
  }

  // Handle "X or Y" format (union types in string form)
  if (normalized.includes(' or ')) {
    const types = normalized.split(' or ').map((t) => t.trim());
    return mapSDEFTypeToTypeScript(types);
  }

  // Map primitive types
  let tsType: string;
  if (SDEF_TO_TS_TYPE_MAP[normalized]) {
    tsType = SDEF_TO_TS_TYPE_MAP[normalized];
  } else {
    // Custom type - convert to PascalCase (e.g., window → Window)
    tsType = toPascalCase(normalized);
  }

  // Wrap in array if list=true
  if (list) {
    return `${tsType}[]`;
  }

  return tsType;
}
