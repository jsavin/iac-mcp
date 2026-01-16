/**
 * MCP Tool Validator
 *
 * Validates MCP tool definitions to ensure compliance with MCP protocol requirements.
 * Catches malformed tool definitions before they are exposed to LLMs.
 *
 * Validation rules:
 * 1. Name: non-empty, alphanumeric + underscores, must start with letter, max 64 chars
 * 2. Description: non-empty, max 500 chars (warn if longer)
 * 3. inputSchema: must have type: "object"
 * 4. Properties: all must have valid JSON Schema types
 * 5. Required: must be subset of properties, must be array
 * 6. No circular references in schema
 * 7. Schema must be JSON-serializable (no functions, undefined, Symbols)
 */

import type {
  MCPTool,
  JSONSchema,
  JSONSchemaProperty,
  ValidationResult,
  ValidationError,
  ValidationWarning,
} from '../../types/mcp-tool.js';

/**
 * Valid JSON Schema property types
 */
const VALID_TYPES = new Set(['string', 'number', 'boolean', 'array', 'object']);

/**
 * ToolValidator class
 *
 * Provides comprehensive validation for MCP tool definitions.
 */
export class ToolValidator {
  /**
   * Validate complete MCP tool
   *
   * Checks tool name, description, and input schema for compliance
   * with MCP protocol requirements.
   *
   * @param tool - MCP tool definition to validate
   * @returns Validation result with errors and warnings
   */
  validate(tool: MCPTool): ValidationResult {
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];

    // Validate name
    errors.push(...this.validateName(tool.name));

    // Validate description
    if (!tool.description || typeof tool.description !== 'string') {
      errors.push({
        field: 'description',
        message: 'Tool description is required',
        severity: 'error',
      });
    } else {
      const descErrors = this.validateDescription(tool.description);
      errors.push(...descErrors);

      // Check for long descriptions (warning only)
      if (tool.description.length > 500) {
        warnings.push({
          field: 'description',
          message: `Description is longer than 500 characters (${tool.description.length} chars). Consider shortening for better LLM understanding.`,
          severity: 'warning',
        });
      }
    }

    // Validate schema
    if (!tool.inputSchema) {
      errors.push({
        field: 'inputSchema',
        message: 'Input schema is required',
        severity: 'error',
      });
    } else {
      const schemaResult = this.validateSchema(tool.inputSchema);
      errors.push(...schemaResult.errors);
      warnings.push(...schemaResult.warnings);
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
    };
  }

  /**
   * Validate tool name
   *
   * Name must be:
   * - Non-empty
   * - Start with a letter
   * - Contain only alphanumeric characters and underscores
   * - Max 64 characters
   *
   * @param name - Tool name to validate
   * @returns Array of validation errors (empty if valid)
   */
  validateName(name: string): ValidationError[] {
    const errors: ValidationError[] = [];

    if (!name || name.trim() === '') {
      errors.push({
        field: 'name',
        message: 'Tool name cannot be empty',
        severity: 'error',
      });
      return errors;
    }

    // Must start with letter
    if (!/^[a-z]/i.test(name)) {
      errors.push({
        field: 'name',
        message: 'Tool name must start with a letter',
        severity: 'error',
      });
    }

    // Only alphanumeric and underscores
    if (!/^[a-z0-9_]+$/i.test(name)) {
      errors.push({
        field: 'name',
        message: 'Tool name must contain only alphanumeric characters and underscores',
        severity: 'error',
      });
    }

    // Max 64 characters
    if (name.length > 64) {
      errors.push({
        field: 'name',
        message: `Tool name must be 64 characters or less (got ${name.length})`,
        severity: 'error',
      });
    }

    return errors;
  }

  /**
   * Validate tool description
   *
   * Description must be:
   * - Non-empty
   * - Not only whitespace
   * - Max 500 characters (warning if longer, handled in validate())
   *
   * @param description - Tool description to validate
   * @returns Array of validation errors (empty if valid)
   */
  validateDescription(description: string): ValidationError[] {
    const errors: ValidationError[] = [];

    if (!description || description.trim() === '') {
      errors.push({
        field: 'description',
        message: 'Tool description cannot be empty',
        severity: 'error',
      });
    }

    return errors;
  }

  /**
   * Validate input schema
   *
   * Schema must:
   * - Have type: "object"
   * - Have valid properties object (if present)
   * - All properties have valid types
   * - Required array is subset of properties
   * - No circular references
   * - Be JSON-serializable
   *
   * @param schema - JSON Schema to validate
   * @returns Validation result with errors and warnings
   */
  validateSchema(schema: JSONSchema): ValidationResult {
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];

    // Check type is "object"
    if (!schema.type) {
      errors.push({
        field: 'inputSchema.type',
        message: 'Input schema must have a type field',
        severity: 'error',
      });
    } else if (schema.type !== 'object') {
      errors.push({
        field: 'inputSchema.type',
        message: 'Input schema type must be "object"',
        severity: 'error',
      });
    }

    // Validate properties
    if (schema.properties !== undefined) {
      if (typeof schema.properties !== 'object' || schema.properties === null) {
        errors.push({
          field: 'inputSchema.properties',
          message: 'Input schema properties must be an object',
          severity: 'error',
        });
      } else {
        // Validate each property
        for (const [propName, prop] of Object.entries(schema.properties)) {
          const propErrors = this.validateSchemaProperty(
            prop,
            `inputSchema.properties.${propName}`
          );
          errors.push(...propErrors);
        }
      }
    }

    // Validate required array
    if (schema.required !== undefined) {
      if (!Array.isArray(schema.required)) {
        errors.push({
          field: 'inputSchema.required',
          message: 'Required field must be an array',
          severity: 'error',
        });
      } else {
        // Check required fields are in properties
        const propertyNames = new Set(Object.keys(schema.properties || {}));
        for (const reqField of schema.required) {
          if (!propertyNames.has(reqField)) {
            errors.push({
              field: 'inputSchema.required',
              message: `Required field "${reqField}" is not defined in properties`,
              severity: 'error',
            });
          }
        }

        // Check for duplicates (warning only)
        const seen = new Set<string>();
        for (const reqField of schema.required) {
          if (seen.has(reqField)) {
            warnings.push({
              field: 'inputSchema.required',
              message: `Duplicate value "${reqField}" in required array`,
              severity: 'warning',
            });
            break; // Only warn once
          }
          seen.add(reqField);
        }
      }
    }

    // Check for circular references
    if (this.detectCircularReferences(schema)) {
      errors.push({
        field: 'inputSchema',
        message: 'Schema contains circular references',
        severity: 'error',
      });
    }

    // Check JSON serializability
    if (!this.isJsonSerializable(schema)) {
      errors.push({
        field: 'inputSchema',
        message: 'Schema must be JSON-serializable (no functions, undefined, or Symbols)',
        severity: 'error',
      });
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
    };
  }

  /**
   * Validate individual schema property
   *
   * Recursively validates property types, nested objects, and arrays.
   *
   * @param prop - Schema property to validate
   * @param path - Property path for error reporting
   * @param visited - Set of visited objects for circular reference detection
   * @returns Array of validation errors
   */
  private validateSchemaProperty(
    prop: JSONSchemaProperty,
    path: string,
    visited: Set<object> = new Set()
  ): ValidationError[] {
    const errors: ValidationError[] = [];

    // Check for circular reference at property level
    if (visited.has(prop)) {
      errors.push({
        field: path,
        message: 'Circular reference detected in property',
        severity: 'error',
      });
      return errors;
    }

    // Validate type
    if (!prop.type) {
      errors.push({
        field: path,
        message: 'Property must have a type',
        severity: 'error',
      });
      return errors;
    }

    if (!VALID_TYPES.has(prop.type)) {
      errors.push({
        field: path,
        message: `Invalid property type "${prop.type}". Must be one of: ${Array.from(VALID_TYPES).join(', ')}`,
        severity: 'error',
      });
      return errors;
    }

    // Validate array items
    if (prop.type === 'array') {
      if (prop.items) {
        const newVisited = new Set(visited);
        newVisited.add(prop);
        const itemErrors = this.validateSchemaProperty(
          prop.items,
          `${path}.items`,
          newVisited
        );
        errors.push(...itemErrors);
      }
    }

    // Validate nested object properties
    if (prop.type === 'object' && prop.properties) {
      const newVisited = new Set(visited);
      newVisited.add(prop);

      for (const [nestedName, nestedProp] of Object.entries(prop.properties)) {
        const nestedErrors = this.validateSchemaProperty(
          nestedProp,
          `${path}.properties.${nestedName}`,
          newVisited
        );
        errors.push(...nestedErrors);
      }
    }

    return errors;
  }

  /**
   * Detect circular references in schema
   *
   * Uses a visited set to track objects and detect cycles.
   * Creates new sets for each branch to properly handle shared references
   * that aren't circular.
   *
   * @param schema - Schema or property to check
   * @param visited - Set of visited objects
   * @returns True if circular reference detected
   */
  private detectCircularReferences(
    schema: JSONSchema | JSONSchemaProperty,
    visited: Set<object> = new Set()
  ): boolean {
    // Primitives and null can't be circular
    if (typeof schema !== 'object' || schema === null) {
      return false;
    }

    // Check if we've seen this exact object before
    if (visited.has(schema)) {
      return true; // Circular reference found
    }

    // Add to visited set
    visited.add(schema);

    // Check properties recursively
    if (schema.properties && typeof schema.properties === 'object') {
      for (const prop of Object.values(schema.properties)) {
        // Create new set for each branch to properly detect circular refs
        const branchVisited = new Set(visited);
        if (this.detectCircularReferences(prop, branchVisited)) {
          return true;
        }
      }
    }

    // Check array items (only JSONSchemaProperty has items)
    if ('items' in schema && schema.items && typeof schema.items === 'object') {
      const branchVisited = new Set(visited);
      if (this.detectCircularReferences(schema.items, branchVisited)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Check if object is JSON-serializable
   *
   * Tests whether an object can be safely serialized to JSON.
   * Detects functions, undefined values, and Symbols.
   *
   * Note: JSON.stringify doesn't throw for functions/undefined/Symbols,
   * it just omits them. We need to recursively check for these.
   *
   * @param obj - Object to check
   * @param visited - Set of visited objects to prevent infinite recursion
   * @returns True if JSON-serializable
   */
  private isJsonSerializable(obj: any, visited: Set<any> = new Set()): boolean {
    // Handle primitives
    if (obj === null) return true;
    if (obj === undefined) return false;

    const type = typeof obj;
    if (type === 'boolean' || type === 'number' || type === 'string') {
      return true;
    }
    if (type === 'function') return false;
    if (type === 'symbol') return false;

    // Handle circular references
    if (visited.has(obj)) {
      return true; // Already checked this branch
    }
    visited.add(obj);

    // Handle arrays
    if (Array.isArray(obj)) {
      return obj.every(item => this.isJsonSerializable(item, new Set(visited)));
    }

    // Handle objects
    if (type === 'object') {
      // Check for Symbol keys
      const symbolKeys = Object.getOwnPropertySymbols(obj);
      if (symbolKeys.length > 0) {
        return false;
      }

      // Check all properties
      for (const key in obj) {
        if (obj.hasOwnProperty(key)) {
          const value = obj[key];
          if (!this.isJsonSerializable(value, new Set(visited))) {
            return false;
          }
        }
      }
      return true;
    }

    // Unknown type
    return false;
  }
}
