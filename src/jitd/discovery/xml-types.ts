/**
 * TypeScript interfaces for SDEF XML structure
 *
 * These types represent the parsed XML structure from fast-xml-parser.
 * The parser is configured with:
 * - attributeNamePrefix: '@_'
 * - ignoreAttributes: false
 * - allowBooleanAttributes: true
 *
 * All attributes are prefixed with '@_' and values are strings (parseAttributeValue: false).
 */

/**
 * Root element of a parsed SDEF file
 */
export interface SDEFXMLRoot {
  dictionary?: SDEFDictionary;
}

/**
 * Dictionary element (root container)
 */
export interface SDEFDictionary {
  '@_title'?: string;
  suite?: SDEFSuite | SDEFSuite[];
}

/**
 * Suite element (container for commands, classes, enumerations)
 */
export interface SDEFSuite {
  '@_name'?: string;
  '@_code'?: string;
  '@_description'?: string;
  command?: SDEFCommand | SDEFCommand[];
  class?: SDEFClass | SDEFClass[];
  enumeration?: SDEFEnumeration | SDEFEnumeration[];
  'class-extension'?: SDEFClassExtension | SDEFClassExtension[];
}

/**
 * Command element
 */
export interface SDEFCommand {
  '@_name'?: string;
  '@_code'?: string;
  '@_description'?: string;
  '@_hidden'?: 'yes' | 'no';
  'direct-parameter'?: SDEFDirectParameter;
  parameter?: SDEFParameter | SDEFParameter[];
  result?: SDEFResult;
}

/**
 * Direct parameter element
 */
export interface SDEFDirectParameter {
  '@_type'?: string;
  '@_description'?: string;
  '@_optional'?: 'yes' | 'no';
  type?: SDEFTypeElement | SDEFTypeElement[];
}

/**
 * Parameter element
 */
export interface SDEFParameter {
  '@_name'?: string;
  '@_code'?: string;
  '@_type'?: string;
  '@_description'?: string;
  '@_optional'?: 'yes' | 'no';
  '@_hidden'?: 'yes' | 'no';
  type?: SDEFTypeElement | SDEFTypeElement[];
}

/**
 * Result element
 */
export interface SDEFResult {
  '@_type'?: string;
  '@_description'?: string;
  type?: SDEFTypeElement | SDEFTypeElement[];
}

/**
 * Type element (child element for union types)
 */
export interface SDEFTypeElement {
  '@_type'?: string;
  '@_list'?: 'yes' | 'no';
}

/**
 * Class element
 */
export interface SDEFClass {
  '@_name'?: string;
  '@_code'?: string;
  '@_description'?: string;
  '@_inherits'?: string;
  '@_hidden'?: 'yes' | 'no';
  '@_plural'?: string;
  property?: SDEFProperty | SDEFProperty[];
  element?: SDEFElement | SDEFElement[];
  'responds-to'?: SDEFRespondsTo | SDEFRespondsTo[];
}

/**
 * Property element
 */
export interface SDEFProperty {
  '@_name'?: string;
  '@_code'?: string;
  '@_type'?: string;
  '@_description'?: string;
  '@_access'?: 'r' | 'w' | 'rw';
  '@_hidden'?: 'yes' | 'no';
  '@_list'?: 'yes' | 'no';
  type?: SDEFTypeElement | SDEFTypeElement[];
}

/**
 * Element element (containment relationship)
 */
export interface SDEFElement {
  '@_type'?: string;
  '@_access'?: 'r' | 'w' | 'rw';
  '@_cocoaKey'?: string;
}

/**
 * Responds-to element (indicates class responds to a command)
 */
export interface SDEFRespondsTo {
  '@_command'?: string;
}

/**
 * Enumeration element
 */
export interface SDEFEnumeration {
  '@_name'?: string;
  '@_code'?: string;
  '@_description'?: string;
  '@_hidden'?: 'yes' | 'no';
  enumerator?: SDEFEnumerator | SDEFEnumerator[];
}

/**
 * Enumerator element (enum value)
 */
export interface SDEFEnumerator {
  '@_name'?: string;
  '@_code'?: string;
  '@_description'?: string;
  '@_hidden'?: 'yes' | 'no';
}

/**
 * Class-extension element
 */
export interface SDEFClassExtension {
  '@_extends'?: string;
  '@_description'?: string;
  property?: SDEFProperty | SDEFProperty[];
  element?: SDEFElement | SDEFElement[];
  'responds-to'?: SDEFRespondsTo | SDEFRespondsTo[];
}
