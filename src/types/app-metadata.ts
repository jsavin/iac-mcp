/**
 * App Metadata Type Definitions
 *
 * Types for lightweight app metadata used in the lazy loading MCP server.
 * These types enable fast listing of available apps without generating full tool definitions.
 *
 * Phase 1 of lazy loading implementation.
 */

import type { MCPTool } from './mcp-tool.js';

/**
 * Lightweight metadata about a scriptable application
 *
 * Used by list_apps tool to quickly show available apps without
 * generating full tool definitions.
 */
export interface AppMetadata {
  /**
   * Human-readable application name (e.g., "Finder", "Safari")
   */
  appName: string;

  /**
   * Application bundle identifier (e.g., "com.apple.finder")
   */
  bundleId: string;

  /**
   * Brief description of the application's scripting capabilities
   */
  description: string;

  /**
   * Total number of scriptable commands/tools available
   */
  toolCount: number;

  /**
   * Names of SDEF suites (command groups)
   */
  suiteNames: string[];
}

/**
 * Response from get_app_tools containing full tool definitions and object model
 *
 * Returned when user requests detailed information about a specific app.
 */
export interface AppToolsResponse {
  /**
   * Application name
   */
  appName: string;

  /**
   * Application bundle identifier
   */
  bundleId: string;

  /**
   * Array of MCP tool definitions for all commands
   */
  tools: MCPTool[];

  /**
   * Object model (classes and enumerations) for understanding app structure
   */
  objectModel: AppObjectModel;
}

/**
 * App Object Model containing classes and enumerations
 *
 * Provides LLM with information about app's object structure
 * and valid enumeration values.
 */
export interface AppObjectModel {
  /**
   * Array of class definitions (objects in the app)
   */
  classes: ClassInfo[];

  /**
   * Array of enumeration definitions (valid values for enum parameters)
   */
  enumerations: EnumerationInfo[];
}

/**
 * Information about a class in the app's object model
 */
export interface ClassInfo {
  /**
   * Class name (e.g., "window", "document")
   */
  name: string;

  /**
   * Four-character AppleScript code
   */
  code: string;

  /**
   * Description of what this class represents
   */
  description: string;

  /**
   * Properties (attributes) of this class
   */
  properties: PropertyInfo[];

  /**
   * Elements (child objects) this class can contain
   */
  elements: ElementInfo[];

  /**
   * Parent class name if this class inherits from another
   */
  inherits?: string;
}

/**
 * Information about a property of a class
 */
export interface PropertyInfo {
  /**
   * Property name (e.g., "name", "visible")
   */
  name: string;

  /**
   * Four-character AppleScript code
   */
  code: string;

  /**
   * Type of the property (e.g., "text", "boolean", "integer")
   */
  type: string;

  /**
   * Description of the property
   */
  description: string;

  /**
   * Whether the property is optional
   */
  optional?: boolean;
}

/**
 * Information about an element (containment) relationship
 */
export interface ElementInfo {
  /**
   * Element name (e.g., "document", "window")
   */
  name: string;

  /**
   * Type of the element (class name)
   */
  type: string;

  /**
   * Description of this element relationship
   */
  description: string;
}

/**
 * Information about an enumeration (set of valid values)
 */
export interface EnumerationInfo {
  /**
   * Enumeration name (e.g., "save options")
   */
  name: string;

  /**
   * Four-character AppleScript code
   */
  code: string;

  /**
   * Description of the enumeration
   */
  description: string;

  /**
   * Array of valid values for this enumeration
   */
  values: EnumeratorInfo[];
}

/**
 * Information about a single enumerator value
 */
export interface EnumeratorInfo {
  /**
   * Enumerator name (e.g., "yes", "no", "ask")
   */
  name: string;

  /**
   * Four-character AppleScript code
   */
  code: string;

  /**
   * Description of this value
   */
  description: string;
}
