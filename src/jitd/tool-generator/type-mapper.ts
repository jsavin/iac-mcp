/**
 * Type Mapper Module
 *
 * Converts SDEF type definitions to JSON Schema properties for MCP tool input schemas.
 *
 * This is a critical component that bridges the gap between macOS AppleScript type system
 * and JSON Schema, enabling LLMs to understand and invoke app commands correctly.
 */

import type { SDEFType, SDEFEnumeration } from '../../types/sdef.js';
import type { TypeMapperOptions } from '../../types/tool-generator.js';

/**
 * JSON Schema Property Definition
 *
 * Represents a single property in a JSON Schema object.
 * Used to define MCP tool input parameters.
 */
export interface JSONSchemaProperty {
  type: 'string' | 'number' | 'boolean' | 'array' | 'object';
  description?: string;
  enum?: string[];
  items?: JSONSchemaProperty;
  properties?: Record<string, JSONSchemaProperty>;
  required?: string[];
  additionalProperties?: boolean;
}

/**
 * Type Mapper
 *
 * Converts SDEF types to JSON Schema properties with proper type mapping,
 * nesting control, and error handling.
 *
 * @example
 * ```typescript
 * const mapper = new TypeMapper({ strictTypeChecking: false, maxNestingDepth: 3 });
 *
 * // Map primitive type
 * const textType = mapper.mapType({ kind: 'primitive', type: 'text' });
 * // → { type: 'string' }
 *
 * // Map list type
 * const listType = mapper.mapType({
 *   kind: 'list',
 *   itemType: { kind: 'primitive', type: 'integer' }
 * });
 * // → { type: 'array', items: { type: 'number' } }
 * ```
 */
export class TypeMapper {
  private readonly strictTypeChecking: boolean;
  private readonly maxNestingDepth: number;

  constructor(options?: TypeMapperOptions) {
    this.strictTypeChecking = options?.strictTypeChecking ?? false;
    this.maxNestingDepth = options?.maxNestingDepth ?? 3;
  }

  /**
   * Map SDEF type to JSON Schema property
   *
   * @param sdefType - The SDEF type to map
   * @param enumerationOrDepth - Either an SDEFEnumeration (for enumeration types) or depth number
   * @param depth - Optional nesting depth (used when second param is enumeration)
   * @returns JSON Schema property definition
   *
   * @example
   * ```typescript
   * // Map a simple type
   * mapper.mapType({ kind: 'primitive', type: 'text' });
   *
   * // Map an enumeration with data
   * mapper.mapType(
   *   { kind: 'enumeration', enumerationName: 'save options' },
   *   { name: 'save options', code: 'savo', enumerators: [...] }
   * );
   * ```
   */
  mapType(
    sdefType: SDEFType,
    enumerationOrDepth?: SDEFEnumeration | number,
    depth?: number
  ): JSONSchemaProperty {
    // Handle null/undefined inputs gracefully
    if (!sdefType) {
      return {
        type: 'string',
        description: 'Unknown type (null or undefined input)',
      };
    }

    // Determine actual depth value
    const currentDepth =
      typeof enumerationOrDepth === 'number' ? enumerationOrDepth : depth ?? 0;

    // Check nesting depth to prevent infinite recursion
    if (currentDepth > this.maxNestingDepth) {
      return {
        type: 'string',
        description: 'Complex nested type (simplified)',
      };
    }

    // Extract enumeration if provided
    const enumeration =
      typeof enumerationOrDepth === 'object' ? enumerationOrDepth : undefined;

    // Map based on type kind
    switch (sdefType.kind) {
      case 'primitive':
        return this.mapPrimitiveType(sdefType.type);

      case 'file':
        return this.mapFileType();

      case 'list':
        return this.mapListType(sdefType.itemType, currentDepth + 1);

      case 'record':
        return this.mapRecordType(sdefType.properties, currentDepth + 1);

      case 'class':
        return this.mapClassReference(sdefType.className);

      case 'enumeration':
        return this.mapEnumeration(sdefType.enumerationName, enumeration);

      default:
        return this.handleUnknownType(sdefType);
    }
  }

  /**
   * Map primitive SDEF types to JSON Schema types
   *
   * @param type - Primitive type name
   * @returns JSON Schema property
   */
  private mapPrimitiveType(
    type: 'text' | 'integer' | 'real' | 'boolean'
  ): JSONSchemaProperty {
    switch (type) {
      case 'text':
        return { type: 'string' };
      case 'integer':
      case 'real':
        return { type: 'number' };
      case 'boolean':
        return { type: 'boolean' };
    }
  }

  /**
   * Map file type to JSON Schema string with file path description
   *
   * @returns JSON Schema property
   */
  private mapFileType(): JSONSchemaProperty {
    return {
      type: 'string',
      description: 'File path',
    };
  }

  /**
   * Map list type to JSON Schema array
   *
   * Recursively maps the item type with depth tracking to prevent infinite recursion.
   *
   * @param itemType - Type of items in the list
   * @param depth - Current nesting depth
   * @returns JSON Schema array property
   */
  private mapListType(
    itemType: SDEFType | undefined,
    depth: number
  ): JSONSchemaProperty {
    // Handle missing itemType gracefully
    if (!itemType) {
      return {
        type: 'array',
        items: { type: 'string' },
      };
    }

    return {
      type: 'array',
      items: this.mapType(itemType, depth),
    };
  }

  /**
   * Map record type to JSON Schema object
   *
   * Recursively maps each property with depth tracking.
   *
   * @param properties - Record properties
   * @param depth - Current nesting depth
   * @returns JSON Schema object property
   */
  private mapRecordType(
    properties: Record<string, SDEFType> | undefined,
    depth: number
  ): JSONSchemaProperty {
    // Handle missing properties gracefully
    if (!properties) {
      return {
        type: 'object',
        properties: {},
      };
    }

    // Map each property recursively
    const mappedProperties: Record<string, JSONSchemaProperty> = {};
    for (const [key, value] of Object.entries(properties)) {
      mappedProperties[key] = this.mapType(value, depth);
    }

    return {
      type: 'object',
      properties: mappedProperties,
    };
  }

  /**
   * Map class reference to JSON Schema object
   *
   * Class references are mapped to generic objects with a descriptive message
   * indicating what class they represent.
   *
   * @param className - Name of the referenced class
   * @returns JSON Schema object property
   */
  private mapClassReference(className: string | undefined): JSONSchemaProperty {
    const name = className || 'unknown class';
    return {
      type: 'object',
      description: `${name} instance`,
    };
  }

  /**
   * Map enumeration type to JSON Schema string with enum constraint
   *
   * If enumeration data is provided, extracts enumerator names as valid values.
   * Otherwise, returns a string type with descriptive message.
   *
   * @param enumerationName - Name of the enumeration
   * @param enumeration - Optional enumeration data with enumerator values
   * @returns JSON Schema string property with enum constraint
   */
  private mapEnumeration(
    enumerationName: string | undefined,
    enumeration?: SDEFEnumeration
  ): JSONSchemaProperty {
    const name = enumerationName || 'unknown enumeration';

    // If enumeration data is provided, extract enumerator values
    if (enumeration?.enumerators && enumeration.enumerators.length > 0) {
      return {
        type: 'string',
        enum: enumeration.enumerators.map((e) => e.name),
      };
    }

    // Otherwise return string with description
    return {
      type: 'string',
      description: `Enumeration: ${name}`,
    };
  }

  /**
   * Handle unknown type with strict checking or fallback
   *
   * @param sdefType - The unknown type
   * @returns JSON Schema string property (fallback)
   * @throws Error if strictTypeChecking is enabled
   */
  private handleUnknownType(sdefType: SDEFType): JSONSchemaProperty {
    const kind = (sdefType as any).kind || 'undefined';

    if (this.strictTypeChecking) {
      throw new Error(`Unknown SDEF type: ${kind}`);
    }

    console.warn(`Unknown SDEF type, defaulting to string:`, sdefType);
    return {
      type: 'string',
      description: `Unknown type: ${kind}`,
    };
  }
}
