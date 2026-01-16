/**
 * Parameter Marshaler
 *
 * Converts JSON parameters from MCP tool calls into JXA-compatible code strings.
 * Handles type conversion, escaping, path detection, and generates valid JXA code.
 */

import type { JSONSchema, JSONSchemaProperty, ToolMetadata } from '../../types/mcp-tool.js';

/**
 * Maximum recursion depth to prevent stack overflow on circular or deeply nested structures.
 * Set to 50 levels which is well beyond normal parameter nesting.
 */
const MAX_RECURSION_DEPTH = 50;

/**
 * Parameter Marshaler class
 *
 * Marshals JSON parameters to JXA-compatible code strings with proper
 * escaping, type conversion, and special handling for file paths.
 */
export class ParameterMarshaler {
  /**
   * Marshal JSON parameters to JXA code
   * @param params - JSON parameters from MCP tool call
   * @param schema - JSON Schema for validation
   * @param _metadata - Tool metadata (for type hints)
   * @returns JXA code representing the parameters
   */
  marshal(
    params: Record<string, any>,
    schema: JSONSchema,
    _metadata: ToolMetadata
  ): string {
    // Marshal the entire params object
    return this.marshalValue(params, schema, new Set(), 0);
  }

  /**
   * Marshal a single value based on JSON Schema type
   * @param value - Value to marshal
   * @param schema - Schema for this value
   * @param seen - Set of seen objects for circular reference detection
   * @param depth - Current recursion depth
   * @returns JXA code string
   * @throws Error if recursion depth exceeds MAX_RECURSION_DEPTH
   */
  marshalValue(value: any, schema: JSONSchemaProperty, seen: Set<any> = new Set(), depth: number = 0): string {
    // Check recursion depth limit
    if (depth > MAX_RECURSION_DEPTH) {
      throw new Error(
        `Recursion depth exceeded MAX_RECURSION_DEPTH (${MAX_RECURSION_DEPTH}). ` +
        `Possible deeply nested or circular structure.`
      );
    }

    // Handle null and undefined
    if (value === null) {
      return 'null';
    }
    if (value === undefined) {
      return 'null';
    }

    // Handle NaN and Infinity
    if (typeof value === 'number') {
      if (Number.isNaN(value) || !Number.isFinite(value)) {
        return 'null';
      }
    }

    // Get the actual type of the value
    const actualType = this.getActualType(value);

    // Handle special object types first
    if (actualType === 'date') {
      return `"${(value as Date).toISOString()}"`;
    }
    if (actualType === 'regexp') {
      return `"${(value as RegExp).toString()}"`;
    }
    if (actualType === 'buffer') {
      return `"${(value as Buffer).toString()}"`;
    }
    if (actualType === 'map') {
      // Convert Map to object
      const obj: Record<string, any> = {};
      (value as Map<any, any>).forEach((v, k) => {
        obj[String(k)] = v;
      });
      return this.marshalValue(obj, { type: 'object', properties: {} }, seen, depth + 1);
    }
    if (actualType === 'set') {
      // Convert Set to array
      const arr = Array.from(value as Set<any>);
      return this.marshalValue(arr, { type: 'array' }, seen, depth + 1);
    }
    if (actualType === 'bigint') {
      return String(value);
    }

    // Handle invalid types
    if (actualType === 'function' || actualType === 'symbol') {
      throw new Error(`Cannot marshal type: ${actualType}`);
    }

    // Handle primitive types
    switch (schema.type) {
      case 'string':
        return this.marshalString(String(value), schema);

      case 'number':
        return this.marshalNumber(value);

      case 'boolean':
        return this.marshalBoolean(value);

      case 'array':
        return this.marshalArray(value, schema, seen, depth + 1);

      case 'object':
        return this.marshalObject(value, schema, seen, depth + 1);

      default:
        // No schema type specified, infer from value
        if (typeof value === 'string') {
          return this.marshalString(value, schema);
        }
        if (typeof value === 'number') {
          return this.marshalNumber(value);
        }
        if (typeof value === 'boolean') {
          return this.marshalBoolean(value);
        }
        if (Array.isArray(value)) {
          return this.marshalArray(value, schema, seen, depth + 1);
        }
        if (typeof value === 'object') {
          return this.marshalObject(value, schema, seen, depth + 1);
        }
        throw new Error(`Cannot marshal value: ${value}`);
    }
  }

  /**
   * Get the actual type of a value
   */
  private getActualType(value: any): string {
    if (value === null) return 'null';
    if (value === undefined) return 'undefined';
    if (Array.isArray(value)) return 'array';
    if (value instanceof Date) return 'date';
    if (value instanceof RegExp) return 'regexp';
    if (typeof Buffer !== 'undefined' && value instanceof Buffer) return 'buffer';
    if (value instanceof Map) return 'map';
    if (value instanceof Set) return 'set';
    if (typeof value === 'bigint') return 'bigint';
    return typeof value;
  }

  /**
   * Marshal a string value
   */
  private marshalString(value: string, schema: JSONSchemaProperty): string {
    // Check if this is a file path
    if (this.isFilePath(value, schema)) {
      // Escape the path string and wrap in Path()
      const escapedPath = this.escapeString(value);
      return `Path("${escapedPath}")`;
    }

    // Regular string - escape and quote
    const escaped = this.escapeString(value);
    return `"${escaped}"`;
  }

  /**
   * Marshal a number value
   */
  private marshalNumber(value: any): string {
    const num = Number(value);
    if (Number.isNaN(num) || !Number.isFinite(num)) {
      return 'null';
    }

    // Convert to string
    let str = String(num);

    // Check if we need to convert scientific notation to decimal
    // But only for small numbers (e.g., 1e-7), not very small ones (e.g., 1e-10)
    if (str.includes('e-')) {
      // Extract the exponent
      const parts = str.split('e-');
      const exponentStr = parts[1];
      if (exponentStr !== undefined) {
        const exponent = parseInt(exponentStr, 10);

        // For smaller exponents (up to 7), convert to decimal
        // For larger exponents, keep scientific notation
        if (exponent <= 7) {
          str = num.toFixed(exponent);
        }
      }
    }

    return str;
  }

  /**
   * Marshal a boolean value
   */
  private marshalBoolean(value: any): string {
    return Boolean(value) ? 'true' : 'false';
  }

  /**
   * Marshal an array value
   */
  private marshalArray(value: any, schema: JSONSchemaProperty, seen: Set<any>, depth: number): string {
    // Check for circular reference
    if (seen.has(value)) {
      throw new Error('Circular reference detected');
    }
    seen.add(value);

    try {
      const arr = Array.isArray(value) ? value : Array.from(value as any);

      if (arr.length === 0) {
        return '[]';
      }

      const items = schema.items || {};
      const marshaledItems: string[] = [];

      // Use for loop to properly handle sparse arrays
      for (let index = 0; index < arr.length; index++) {
        // Check if index exists in array (handles sparse arrays)
        if (index in arr) {
          marshaledItems.push(this.marshalValue(arr[index], items as JSONSchemaProperty, new Set(seen), depth + 1));
        } else {
          marshaledItems.push('null');
        }
      }

      return `[${marshaledItems.join(', ')}]`;
    } finally {
      seen.delete(value);
    }
  }

  /**
   * Marshal an object value
   */
  private marshalObject(value: any, schema: JSONSchemaProperty, seen: Set<any>, depth: number): string {
    // Check for circular reference
    if (seen.has(value)) {
      throw new Error('Circular reference detected');
    }
    seen.add(value);

    try {
      const properties = schema.properties || {};

      // Get object keys, filtering out dangerous keys
      const keys = Object.keys(value).filter(key => {
        // Filter out prototype pollution attempts
        return key !== '__proto__' && key !== 'constructor' && key !== 'prototype';
      });

      if (keys.length === 0) {
        return '{}';
      }

      const pairs: string[] = [];

      for (const key of keys) {
        const val = value[key];

        // Skip undefined values
        if (val === undefined) {
          continue;
        }

        // Get schema for this property
        const propSchema = properties[key] || this.inferSchema(val);

        // Check if this property might be a file path
        const enhancedSchema = this.enhanceSchemaForPath(key, propSchema);

        // Marshal the value
        const marshaledValue = this.marshalValue(val, enhancedSchema, new Set(seen), depth + 1);

        // Generate the key:value pair
        // For JXA object literals, we use key: value syntax (no quotes on keys unless special chars)
        const safeKey = this.isValidIdentifier(key) ? key : `"${this.escapeString(key)}"`;
        pairs.push(`${safeKey}: ${marshaledValue}`);
      }

      return `{${pairs.join(', ')}}`;
    } finally {
      seen.delete(value);
    }
  }

  /**
   * Check if a string value is a file path
   *
   * Performs validation to ensure the path is safe and not attempting
   * directory traversal or access to restricted system directories.
   *
   * @param value - The path value to check
   * @param schema - The schema for this field
   * @returns true if this appears to be a file path, false otherwise
   * @throws Error if the path appears to be a traversal or restricted access attempt
   */
  private isFilePath(value: string, schema: JSONSchemaProperty): boolean {
    // Empty strings are not paths
    if (value === '') {
      return false;
    }

    // Check if this looks like a path first before doing path traversal checks
    const looksLikePath = value.startsWith('/') ||
        value.startsWith('~/') ||
        value.startsWith('./') ||
        value.startsWith('../');

    // If it doesn't look like a path but schema suggests it, still validate it
    const schemaIndicatesPath = schema.description && (
      schema.description.toLowerCase().includes('path') ||
      schema.description.toLowerCase().includes('file') ||
      schema.description.toLowerCase().includes('directory')
    );

    if (!looksLikePath && !schemaIndicatesPath) {
      return false;
    }

    // Validate the path to prevent directory traversal attacks
    this.validatePathSecurity(value);

    return true;
  }

  /**
   * Validate path security to prevent traversal and unauthorized access
   *
   * Rejects paths that attempt:
   * - Directory traversal: ../ or ..\
   * - Access to restricted system directories: /etc, /System, /private
   *
   * @param path - The path to validate
   * @throws Error if the path is detected as unsafe
   */
  private validatePathSecurity(path: string): void {
    // Normalize path separators for checking
    const normalizedPath = path.replace(/\\/g, '/');

    // Check for directory traversal patterns
    if (normalizedPath.includes('../') || normalizedPath.includes('..\\')) {
      throw new Error(
        'Invalid path: contains directory traversal pattern (../). ' +
        'Cannot access parent directories for security reasons.'
      );
    }

    // Check for access to restricted system directories
    const restrictedDirs = ['/etc/', '/System/', '/private/'];
    for (const restrictedDir of restrictedDirs) {
      if (normalizedPath.startsWith(restrictedDir)) {
        throw new Error(
          `Invalid path: cannot access restricted system directory (${restrictedDir}). ` +
          'Access to system directories is not permitted for security reasons.'
        );
      }
    }
  }

  /**
   * Enhance schema to add path hint for known parameter names
   */
  private enhanceSchemaForPath(key: string, schema: JSONSchemaProperty): JSONSchemaProperty {
    // Known path parameter names
    const pathParamNames = ['target', 'to', 'from', 'path', 'file', 'directory', 'folder'];

    if (pathParamNames.includes(key.toLowerCase()) && schema.type === 'string') {
      return {
        ...schema,
        description: schema.description || 'File path'
      };
    }

    return schema;
  }

  /**
   * Escape special characters in strings for JXA
   */
  private escapeString(str: string): string {
    return str
      .replace(/\\/g, '\\\\')         // Backslash must be first
      .replace(/"/g, '\\"')            // Double quotes
      .replace(/\n/g, '\\n')           // Newline
      .replace(/\r/g, '\\r')           // Carriage return
      .replace(/\t/g, '\\t')           // Tab
      .replace(/\f/g, '\\f')           // Form feed
      .replace(/[\b]/g, '\\b');        // Backspace (use character class to avoid word boundary)
  }

  /**
   * Check if a string is a valid JavaScript identifier
   */
  private isValidIdentifier(str: string): boolean {
    // JavaScript identifier rules: start with letter, $, or _, then letters, digits, $, _
    return /^[a-zA-Z_$][a-zA-Z0-9_$]*$/.test(str);
  }

  /**
   * Infer schema from value type
   */
  private inferSchema(value: any): JSONSchemaProperty {
    if (value === null || value === undefined) {
      return { type: 'string' };
    }
    if (typeof value === 'string') {
      return { type: 'string' };
    }
    if (typeof value === 'number') {
      return { type: 'number' };
    }
    if (typeof value === 'boolean') {
      return { type: 'boolean' };
    }
    if (Array.isArray(value)) {
      return { type: 'array' };
    }
    if (typeof value === 'object') {
      return { type: 'object', properties: {} };
    }
    return { type: 'string' };
  }
}
