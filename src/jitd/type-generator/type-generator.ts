/**
 * TypeScript Type Generator
 *
 * Generates TypeScript interface and enum definitions from SDEF class and enumeration data.
 * This is Phase 1 of object model exposure - generating types that LLMs can use to understand
 * app object structures.
 */

import type { ClassInfo, EnumerationInfo } from '../../types/app-metadata.js';
import { toCamelCase, toPascalCase } from './naming.js';
import { mapSDEFTypeToTypeScript } from './type-mapper.js';

/**
 * TypeScript reserved keywords that need escaping
 */
const RESERVED_KEYWORDS = new Set([
  'break',
  'case',
  'catch',
  'class',
  'const',
  'continue',
  'debugger',
  'default',
  'delete',
  'do',
  'else',
  'enum',
  'export',
  'extends',
  'false',
  'finally',
  'for',
  'function',
  'if',
  'import',
  'in',
  'instanceof',
  'new',
  'null',
  'return',
  'super',
  'switch',
  'this',
  'throw',
  'true',
  'try',
  'typeof',
  'var',
  'void',
  'while',
  'with',
  'yield',
  'let',
  'static',
  'implements',
  'interface',
  'package',
  'private',
  'protected',
  'public',
  'type',
  'namespace',
  'abstract',
  'as',
  'async',
  'await',
  'constructor',
  'declare',
  'from',
  'get',
  'is',
  'keyof',
  'module',
  'readonly',
  'require',
  'set',
  'symbol',
  'unique',
]);

/**
 * Escape TypeScript reserved keywords by appending underscore
 *
 * @param name - Property or identifier name
 * @returns Escaped name if reserved, original name otherwise
 */
function escapeReservedKeyword(name: string): string {
  if (RESERVED_KEYWORDS.has(name)) {
    return `${name}_`;
  }
  return name;
}

/**
 * Format JSDoc comment block
 *
 * Handles multi-line descriptions and unicode characters.
 *
 * @param description - Description text (may contain newlines)
 * @returns Formatted JSDoc comment
 */
function formatJSDoc(description: string): string {
  if (!description || description.trim() === '') {
    return '';
  }

  const lines = description.trim().split('\n');

  if (lines.length === 1) {
    return `/**\n * ${lines[0]}\n */`;
  }

  // Multi-line comment
  const commentLines = ['/**', ...lines.map((line) => ` * ${line}`), ' */'];
  return commentLines.join('\n');
}

/**
 * Generate TypeScript enum from enumeration definition
 *
 * Converts SDEF enumeration to TypeScript enum with:
 * - PascalCase enum name
 * - PascalCase enumerator names
 * - JSDoc comments from descriptions
 * - String literal values (four-character codes)
 *
 * @param enumDef - Enumeration definition from SDEF
 * @returns TypeScript enum code
 *
 * @example
 * // Input: save options enum with yes/no values
 * // Output:
 * // /**
 * //  * save options enumeration
 * //  *\/
 * // enum SaveOptions {
 * //   /** Save the file *\/
 * //   Yes = "yes ",
 * //   /** Do not save *\/
 * //   No = "no  "
 * // }
 */
export function generateEnum(enumDef: EnumerationInfo): string {
  const enumName = toPascalCase(enumDef.name);
  const lines: string[] = [];

  // JSDoc comment for enum
  if (enumDef.description && enumDef.description.trim() !== '') {
    lines.push(formatJSDoc(enumDef.description));
  }

  // Enum declaration
  lines.push(`enum ${enumName} {`);

  // Generate enumerator values
  enumDef.values.forEach((enumerator, index) => {
    const enumeratorName = toPascalCase(enumerator.name);
    const isLast = index === enumDef.values.length - 1;

    // JSDoc comment for enumerator (if description exists)
    if (enumerator.description && enumerator.description.trim() !== '') {
      lines.push(`  ${formatJSDoc(enumerator.description).replace(/\n/g, '\n  ')}`);
    }

    // Enumerator line
    const comma = isLast ? '' : ',';
    lines.push(`  ${enumeratorName} = "${enumerator.code}"${comma}`);
  });

  lines.push('}');

  return lines.join('\n');
}

/**
 * Generate TypeScript interface from class definition
 *
 * Converts SDEF class to TypeScript interface with:
 * - PascalCase interface name
 * - camelCase property names
 * - All properties optional (?)
 * - readonly modifier for read-only properties
 * - JSDoc comments from descriptions
 * - extends clause for inheritance
 *
 * @param classDef - Class definition from SDEF
 * @returns TypeScript interface code
 *
 * @example
 * // Input: window class with name and visible properties
 * // Output:
 * // /**
 * //  * window class
 * //  *\/
 * // interface Window {
 * //   /** Window title *\/
 * //   name?: string;
 * //
 * //   /** Is window visible *\/
 * //   visible?: boolean;
 * // }
 */
export function generateInterface(classDef: ClassInfo): string {
  const interfaceName = toPascalCase(classDef.name);
  const lines: string[] = [];

  // JSDoc comment for interface
  if (classDef.description && classDef.description.trim() !== '') {
    lines.push(formatJSDoc(classDef.description));
  }

  // Interface declaration
  let declaration = `interface ${interfaceName}`;
  if (classDef.inherits) {
    const parentName = toPascalCase(classDef.inherits);
    declaration += ` extends ${parentName}`;
  }
  lines.push(declaration + ' {');

  // Generate properties
  classDef.properties.forEach((property, index) => {
    let propertyName = toCamelCase(property.name);

    // Escape reserved keywords
    propertyName = escapeReservedKeyword(propertyName);

    // Determine if readonly (properties like 'id' are typically readonly)
    // For Phase 1, we'll mark properties with names like 'id', 'class', 'properties' as readonly
    const readonlyKeywords = ['id', 'class', 'properties'];
    const isReadonly = readonlyKeywords.includes(property.name.toLowerCase());

    // Map type
    const tsType = mapSDEFTypeToTypeScript(property.type);

    // JSDoc comment (if description exists)
    if (property.description && property.description.trim() !== '') {
      // Add blank line before property (except first)
      if (index > 0) {
        lines.push('');
      }
      lines.push(`  ${formatJSDoc(property.description).replace(/\n/g, '\n  ')}`);
    }

    // Property line
    const readonly = isReadonly ? 'readonly ' : '';
    lines.push(`  ${readonly}${propertyName}?: ${tsType};`);
  });

  lines.push('}');

  return lines.join('\n');
}

/**
 * Generate complete TypeScript type definitions from classes and enumerations
 *
 * Generates:
 * 1. All enum definitions (enumerations first, to avoid forward references)
 * 2. All interface definitions (classes)
 * 3. Blank lines between declarations for readability
 *
 * @param classes - Array of class definitions
 * @param enumerations - Array of enumeration definitions
 * @returns Complete TypeScript code as string
 *
 * @example
 * const types = generateTypeScriptTypes(
 *   [windowClass, documentClass],
 *   [saveOptionsEnum, statusEnum]
 * );
 * // Returns:
 * // enum SaveOptions { ... }
 * //
 * // enum Status { ... }
 * //
 * // interface Window { ... }
 * //
 * // interface Document { ... }
 */
export function generateTypeScriptTypes(
  classes: ClassInfo[],
  enumerations: EnumerationInfo[]
): string {
  const declarations: string[] = [];

  // Generate enums first (to avoid forward reference issues)
  enumerations.forEach((enumDef) => {
    declarations.push(generateEnum(enumDef));
  });

  // Generate interfaces
  classes.forEach((classDef) => {
    declarations.push(generateInterface(classDef));
  });

  // Join with blank lines between declarations
  return declarations.join('\n\n');
}
