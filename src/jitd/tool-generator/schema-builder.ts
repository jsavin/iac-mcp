/**
 * Schema Builder Module
 *
 * Constructs JSON Schema from SDEF commands for MCP tool input schemas.
 *
 * This module handles the conversion of SDEF command parameters into properly
 * structured JSON Schema objects that MCP servers can use to validate tool inputs.
 * It supports both direct parameters and named parameters, with proper handling
 * of optional/required fields and automatic description generation.
 */

import type { SDEFCommand, SDEFParameter } from '../../types/sdef.js';
import { TypeMapper, type JSONSchemaProperty } from './type-mapper.js';
import type { SchemaBuilderOptions } from '../../types/tool-generator.js';

/**
 * JSON Schema Definition
 *
 * Represents a complete JSON Schema object for MCP tool input validation.
 * Always has root type 'object' with properties and optional required array.
 */
export interface JSONSchema {
  type: 'object';
  properties: Record<string, JSONSchemaProperty>;
  required?: string[];
  additionalProperties?: boolean;
}

/**
 * Schema Builder
 *
 * Constructs JSON Schema from SDEF commands with support for:
 * - Direct parameters (mapped to configurable property name, default "target")
 * - Named parameters (mapped to their sanitized names)
 * - Optional/required parameter handling
 * - Automatic description generation for missing descriptions
 * - Description truncation for overly long descriptions
 *
 * @example
 * ```typescript
 * const mapper = new TypeMapper();
 * const builder = new SchemaBuilder(mapper, {
 *   maxDescriptionLength: 500,
 *   generateMissingDescriptions: true,
 *   directParameterName: 'target'
 * });
 *
 * const command: SDEFCommand = {
 *   name: 'open',
 *   code: 'aevtodoc',
 *   parameters: [
 *     {
 *       name: 'using',
 *       code: 'usin',
 *       type: { kind: 'primitive', type: 'text' },
 *       description: 'the application to open with',
 *       optional: true
 *     }
 *   ],
 *   directParameter: {
 *     name: 'direct-parameter',
 *     code: '----',
 *     type: { kind: 'file' },
 *     description: 'the file to open',
 *     optional: false
 *   }
 * };
 *
 * const schema = builder.buildInputSchema(command);
 * // {
 * //   type: 'object',
 * //   properties: {
 * //     target: { type: 'string', description: 'the file to open' },
 * //     using: { type: 'string', description: 'the application to open with' }
 * //   },
 * //   required: ['target']
 * // }
 * ```
 */
export class SchemaBuilder {
  private readonly typeMapper: TypeMapper;
  private readonly maxDescriptionLength: number;
  private readonly generateMissingDescriptions: boolean;
  private readonly directParameterName: string;

  /**
   * Create a new SchemaBuilder
   *
   * @param typeMapper - Optional TypeMapper instance (creates new one if not provided)
   * @param options - Optional configuration options
   */
  constructor(typeMapper?: TypeMapper, options?: SchemaBuilderOptions) {
    this.typeMapper = typeMapper || new TypeMapper();
    this.maxDescriptionLength = options?.maxDescriptionLength ?? 500;
    this.generateMissingDescriptions = options?.generateMissingDescriptions ?? true;
    this.directParameterName = options?.directParameterName ?? 'target';
  }

  /**
   * Build input schema from SDEF command
   *
   * Constructs a complete JSON Schema object from a command's parameters.
   * The schema includes both direct and named parameters with proper type
   * mapping, descriptions, and required field handling.
   *
   * @param command - SDEF command to build schema from
   * @returns Complete JSON Schema for tool input validation
   *
   * @example
   * ```typescript
   * const schema = builder.buildInputSchema({
   *   name: 'quit',
   *   code: 'aevtquit',
   *   parameters: []
   * });
   * // → { type: 'object', properties: {} }
   * ```
   */
  buildInputSchema(command: SDEFCommand): JSONSchema {
    const properties = this.buildProperties(
      command.parameters || [],
      command.directParameter,
      command.name
    );

    const required = this.extractRequired(
      command.parameters || [],
      command.directParameter
    );

    const schema: JSONSchema = {
      type: 'object',
      properties,
    };

    // Only include required array if there are required parameters
    if (required.length > 0) {
      schema.required = required;
    }

    return schema;
  }

  /**
   * Build properties object from parameters
   *
   * Converts both direct and named parameters into a properties object
   * suitable for JSON Schema. Direct parameter is always added first if
   * present, followed by named parameters in order.
   *
   * @param parameters - Array of named parameters
   * @param directParam - Optional direct parameter
   * @param commandName - Optional command name for context in generated descriptions
   * @returns Properties object for JSON Schema
   */
  private buildProperties(
    parameters: SDEFParameter[],
    directParam?: SDEFParameter,
    commandName?: string
  ): Record<string, JSONSchemaProperty> {
    const properties: Record<string, JSONSchemaProperty> = {};

    // Add direct parameter first if present
    if (directParam) {
      const { name, schema } = this.handleDirectParameter(directParam, commandName);
      properties[name] = schema;
    }

    // Add named parameters
    for (const param of parameters) {
      const paramName = this.sanitizeParameterName(param.name);
      const schema = this.typeMapper.mapType(param.type);

      // Add description if available or if generation is enabled
      if (param.description || this.generateMissingDescriptions) {
        schema.description = this.generateDescription(param, commandName);
      }

      properties[paramName] = schema;
    }

    return properties;
  }

  /**
   * Extract required parameter names
   *
   * Determines which parameters are required (not optional) and returns
   * their names. Direct parameter uses the configured directParameterName,
   * while named parameters use their sanitized names.
   *
   * @param parameters - Array of named parameters
   * @param directParam - Optional direct parameter
   * @returns Array of required parameter names (empty if none required)
   */
  private extractRequired(
    parameters: SDEFParameter[],
    directParam?: SDEFParameter
  ): string[] {
    const required: string[] = [];

    // Direct parameter is required unless marked optional
    if (directParam && !directParam.optional) {
      required.push(this.directParameterName);
    }

    // Add required named parameters
    for (const param of parameters) {
      if (!param.optional) {
        required.push(this.sanitizeParameterName(param.name));
      }
    }

    return required;
  }

  /**
   * Handle direct parameter
   *
   * Processes a direct parameter by mapping its type and generating a
   * description. Direct parameters are given a configurable name
   * (default: "target") in the resulting schema.
   *
   * @param directParam - Direct parameter to process
   * @param commandName - Optional command name for context in generated descriptions
   * @returns Object with parameter name and schema
   */
  private handleDirectParameter(
    directParam: SDEFParameter,
    commandName?: string
  ): {
    name: string;
    schema: JSONSchemaProperty;
  } {
    const schema = this.typeMapper.mapType(directParam.type);

    // Add description if available or if generation is enabled
    if (directParam.description || this.generateMissingDescriptions) {
      schema.description = this.generateDescription(directParam, commandName);
    }

    return {
      name: this.directParameterName,
      schema,
    };
  }

  /**
   * Generate description for parameter
   *
   * Creates a description for a parameter, using the SDEF description if
   * available, or generating a fallback description if enabled. Truncates
   * overly long descriptions to the configured maximum length.
   *
   * @param param - Parameter to generate description for
   * @param commandName - Optional command name for context in generated descriptions
   * @returns Description string (may be truncated)
   *
   * @example
   * ```typescript
   * // With SDEF description
   * generateDescription({ name: 'to', description: 'destination folder', ... })
   * // → 'destination folder'
   *
   * // Without description (if generation enabled)
   * generateDescription({ name: 'to', ... }, 'move')
   * // → 'to parameter for move'
   * ```
   */
  private generateDescription(param: SDEFParameter, commandName?: string): string {
    let description = param.description || '';

    // Generate fallback description if missing and generation is enabled
    if (!description && this.generateMissingDescriptions) {
      description = `${param.name} parameter`;
      if (commandName) {
        description += ` for ${commandName}`;
      }
    }

    // Truncate if exceeds maximum length
    if (description.length > this.maxDescriptionLength) {
      description = description.substring(0, this.maxDescriptionLength - 3) + '...';
    }

    return description;
  }

  /**
   * Sanitize parameter name
   *
   * Cleans up parameter names to be valid JSON Schema property names.
   * This implementation preserves spaces and special characters that appear
   * in SDEF parameter names (like "routing suppressed" or "with-dashes")
   * rather than converting them to underscores.
   *
   * Based on test expectations, parameter names should be preserved as-is
   * from SDEF files, including spaces and dashes.
   *
   * @param name - Parameter name to sanitize
   * @returns Sanitized parameter name
   *
   * @example
   * ```typescript
   * sanitizeParameterName('routing suppressed')  // → 'routing suppressed'
   * sanitizeParameterName('with-dashes')         // → 'with-dashes'
   * sanitizeParameterName('simple')              // → 'simple'
   * ```
   */
  private sanitizeParameterName(name: string): string {
    // Based on test expectations, we preserve the name as-is
    // Tests show that names like "routing suppressed" and "with-dashes"
    // should remain unchanged
    return name;
  }
}
