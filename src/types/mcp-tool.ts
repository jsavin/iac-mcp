/**
 * MCP Tool Type Definitions
 *
 * Defines the structure of MCP (Model Context Protocol) tool definitions
 * that will be generated from SDEF data.
 */

import type { SDEFType } from './sdef.js';

/**
 * JSON Schema property types supported by MCP
 */
export type JSONSchemaPropertyType = 'string' | 'number' | 'boolean' | 'array' | 'object';

/**
 * JSON Schema property definition
 *
 * Represents a single property in a JSON Schema object.
 * Supports basic types, arrays, objects, and enumerations.
 */
export interface JSONSchemaProperty {
  type: JSONSchemaPropertyType;
  description?: string;
  enum?: string[];
  items?: JSONSchemaProperty;
  properties?: Record<string, JSONSchemaProperty>;
  required?: string[];
  additionalProperties?: boolean;
}

/**
 * MCP Tool Input Schema
 *
 * JSON Schema for validating tool input parameters.
 * Must have type "object" at root level per MCP specification.
 */
export interface JSONSchema {
  type: 'object';
  properties: Record<string, JSONSchemaProperty>;
  required?: string[];
  additionalProperties?: boolean;
}

/**
 * MCP Tool Definition
 *
 * Complete tool definition following MCP protocol specification.
 * Tools represent capabilities that can be invoked by LLMs.
 */
export interface MCPTool {
  /**
   * Unique tool identifier
   * Format: {appName}_{commandName} (e.g., "finder_open")
   * Must be alphanumeric with underscores, max 64 chars
   */
  name: string;

  /**
   * Human-readable description of what the tool does
   * Used by LLM to understand tool capabilities
   * Should be clear and concise (max 500 chars recommended)
   */
  description: string;

  /**
   * JSON Schema defining the tool's input parameters
   * Must have type "object" at root level
   */
  inputSchema: JSONSchema;

  /**
   * Optional metadata for execution layer (Week 3)
   * Not part of MCP spec, but useful for tracking and execution
   */
  _metadata?: ToolMetadata;
}

/**
 * Tool Metadata
 *
 * Additional information about the tool for execution and debugging.
 * Not part of MCP specification, but useful for implementation.
 */
export interface ToolMetadata {
  /**
   * Application name (e.g., "Finder")
   */
  appName: string;

  /**
   * Application bundle identifier (e.g., "com.apple.finder")
   */
  bundleId: string;

  /**
   * Original SDEF command name
   */
  commandName: string;

  /**
   * AppleScript four/eight-character code
   */
  commandCode: string;

  /**
   * Suite name from SDEF
   */
  suiteName: string;

  /**
   * Name of direct parameter if present
   */
  directParameterName?: string;

  /**
   * Result type from SDEF command
   */
  resultType?: SDEFType;
}

/**
 * Validation Error
 *
 * Represents a blocking validation error that prevents tool from working.
 */
export interface ValidationError {
  /**
   * Which field has the error
   */
  field: string;

  /**
   * Description of the error
   */
  message: string;

  /**
   * Always 'error' for blocking issues
   */
  severity: 'error';
}

/**
 * Validation Warning
 *
 * Represents a non-blocking validation warning.
 */
export interface ValidationWarning {
  /**
   * Which field has the warning
   */
  field: string;

  /**
   * Description of the warning
   */
  message: string;

  /**
   * Always 'warning' for non-blocking issues
   */
  severity: 'warning';
}

/**
 * Validation Result
 *
 * Result of validating an MCP tool definition.
 */
export interface ValidationResult {
  /**
   * True if no blocking errors (warnings are OK)
   */
  valid: boolean;

  /**
   * Blocking validation errors
   */
  errors: ValidationError[];

  /**
   * Non-blocking validation warnings
   */
  warnings: ValidationWarning[];
}
