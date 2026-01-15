/**
 * Type definitions for SDEF (Scripting Definition) files
 *
 * These types represent the structure of macOS SDEF XML files
 * that define scriptable application capabilities.
 */

/**
 * Top-level SDEF dictionary
 */
export interface SDEFDictionary {
  title: string;
  suites: SDEFSuite[];
}

/**
 * Suite - a collection of related commands, classes, and enumerations
 */
export interface SDEFSuite {
  name: string;
  code: string; // Four-character code
  description?: string;
  commands: SDEFCommand[];
  classes: SDEFClass[];
  enumerations: SDEFEnumeration[];
}

/**
 * Command - an operation that can be performed
 */
export interface SDEFCommand {
  name: string;
  code: string; // Four-character code
  description?: string;
  parameters: SDEFParameter[];
  result?: SDEFType;
  directParameter?: SDEFParameter;
}

/**
 * Parameter - input to a command
 */
export interface SDEFParameter {
  name: string;
  code: string; // Four-character code
  type: SDEFType;
  description?: string;
  optional?: boolean;
}

/**
 * Type system for SDEF types
 */
export type SDEFType =
  | { kind: 'primitive'; type: 'text' | 'integer' | 'real' | 'boolean' }
  | { kind: 'file' }
  | { kind: 'list'; itemType: SDEFType }
  | { kind: 'record'; properties: Record<string, SDEFType> }
  | { kind: 'class'; className: string }
  | { kind: 'enumeration'; enumerationName: string };

/**
 * Class - object type in the app's object model
 */
export interface SDEFClass {
  name: string;
  code: string; // Four-character code
  description?: string;
  properties: SDEFProperty[];
  elements: SDEFElement[];
}

/**
 * Property - attribute of a class
 */
export interface SDEFProperty {
  name: string;
  code: string; // Four-character code
  type: SDEFType;
  description?: string;
  access: 'r' | 'w' | 'rw';
}

/**
 * Element - child objects of a class
 */
export interface SDEFElement {
  type: string; // Class name
  access: 'r' | 'w' | 'rw';
}

/**
 * Enumeration - a set of named values
 */
export interface SDEFEnumeration {
  name: string;
  code: string; // Four-character code
  enumerators: SDEFEnumerator[];
}

/**
 * Enumerator - a single value in an enumeration
 */
export interface SDEFEnumerator {
  name: string;
  code: string; // Four-character code
  description?: string;
}
