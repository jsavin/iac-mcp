/**
 * Types for parsed SDEF classes
 *
 * These represent the simplified, parsed form of SDEF classes
 * after XML parsing, suitable for tool generation and object model exposure.
 */

/**
 * Parsed class definition from SDEF
 */
export interface ParsedClass {
  name: string;
  code: string;
  inherits?: string;
  description?: string;
  properties: ParsedProperty[];
  elements: ParsedElement[];
  hidden?: boolean;
}

/**
 * Parsed property definition
 */
export interface ParsedProperty {
  name: string;
  code: string;
  type: string | string[]; // Single type or union of types
  list?: boolean; // True if this is a list type
  access?: 'r' | 'w' | 'rw';
  description?: string;
  hidden?: boolean;
}

/**
 * Parsed element (child object) definition
 */
export interface ParsedElement {
  type: string; // Class name
  cocoaKey?: string; // Cocoa key for accessing the element
}

/**
 * Parsed enumeration definition
 */
export interface ParsedEnumeration {
  name: string;
  code: string;
  enumerators: {
    name: string;
    code: string;
    description?: string;
  }[];
}

/**
 * Class extension that adds properties/elements to an existing class
 */
export interface ClassExtension {
  extends: string; // Name of class being extended
  properties: ParsedProperty[];
  elements: ParsedElement[];
}
