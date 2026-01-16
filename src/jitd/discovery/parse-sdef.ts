/**
 * SDEF XML Parser
 *
 * Parses macOS SDEF (Scripting Definition) XML files and extracts
 * structured data about application capabilities.
 */

import { readFile } from 'fs/promises';
import { XMLParser } from 'fast-xml-parser';
import type {
  SDEFDictionary,
  SDEFSuite,
  SDEFCommand,
  SDEFParameter,
  SDEFClass,
  SDEFProperty,
  SDEFElement,
  SDEFEnumeration,
  SDEFEnumerator,
  SDEFType,
} from '../../types/sdef.js';

/**
 * SDEF Parser - extracts structured data from SDEF XML files
 */
export class SDEFParser {
  private parser: XMLParser;
  private parseCache: Map<string, SDEFDictionary>;

  constructor() {
    // Configure XML parser
    this.parser = new XMLParser({
      ignoreAttributes: false,
      attributeNamePrefix: '@_',
      textNodeName: '#text',
      parseAttributeValue: false, // Keep as strings for type safety
      trimValues: false, // Don't trim - four-character codes may have trailing spaces
      ignoreDeclaration: true,
      ignorePiTags: true,
    });

    this.parseCache = new Map();
  }

  /**
   * Parse SDEF file and return structured data
   */
  async parse(sdefPath: string): Promise<SDEFDictionary> {
    // Check cache first
    const cached = this.parseCache.get(sdefPath);
    if (cached) {
      return cached;
    }

    try {
      const xmlContent = await readFile(sdefPath, 'utf-8');
      const result = await this.parseContent(xmlContent);

      // Cache the result
      this.parseCache.set(sdefPath, result);

      return result;
    } catch (error) {
      if (error instanceof Error) {
        throw new Error(`Failed to parse SDEF file at ${sdefPath}: ${error.message}`);
      }
      throw error;
    }
  }

  /**
   * Parse SDEF XML content directly
   */
  async parseContent(xmlContent: string): Promise<SDEFDictionary> {
    try {
      const parsed = this.parser.parse(xmlContent);

      if (!parsed.dictionary) {
        throw new Error('Invalid SDEF format: missing <dictionary> root element');
      }

      return this.parseDictionary(parsed.dictionary);
    } catch (error) {
      if (error instanceof Error) {
        throw new Error(`Failed to parse SDEF XML: ${error.message}`);
      }
      throw error;
    }
  }

  /**
   * Parse top-level dictionary element
   */
  private parseDictionary(dict: any): SDEFDictionary {
    // Title is optional - some SDEFs (like Finder) don't have it
    const title = dict['@_title'] || 'Untitled';

    // Parse all suites
    const suites: SDEFSuite[] = [];
    const suiteElements = this.ensureArray(dict.suite);

    for (const suiteEl of suiteElements) {
      if (suiteEl) {
        suites.push(this.parseSuite(suiteEl));
      }
    }

    return {
      title,
      suites,
    };
  }

  /**
   * Parse suite element
   */
  private parseSuite(suite: any): SDEFSuite {
    const name = suite['@_name'];
    const code = suite['@_code'];

    if (!name || !code) {
      throw new Error('Suite missing required "name" or "code" attribute');
    }

    this.validateFourCharCode(code, 'suite', name);

    // Parse commands
    const commands: SDEFCommand[] = [];
    const commandElements = this.ensureArray(suite.command);
    for (const cmdEl of commandElements) {
      if (cmdEl) {
        commands.push(this.parseCommand(cmdEl));
      }
    }

    // Parse classes
    const classes: SDEFClass[] = [];
    const classElements = this.ensureArray(suite.class);
    for (const classEl of classElements) {
      if (classEl) {
        classes.push(this.parseClass(classEl));
      }
    }

    // Parse enumerations
    const enumerations: SDEFEnumeration[] = [];
    const enumElements = this.ensureArray(suite.enumeration);
    for (const enumEl of enumElements) {
      if (enumEl) {
        enumerations.push(this.parseEnumeration(enumEl));
      }
    }

    return {
      name,
      code,
      description: suite['@_description'],
      commands,
      classes,
      enumerations,
    };
  }

  /**
   * Parse command element
   */
  private parseCommand(cmd: any): SDEFCommand {
    const name = cmd['@_name'];
    const code = cmd['@_code'];

    if (!name || !code) {
      throw new Error('Command missing required "name" or "code" attribute');
    }

    this.validateFourCharCode(code, 'command', name);

    // Parse parameters
    const parameters: SDEFParameter[] = [];
    const paramElements = this.ensureArray(cmd.parameter);
    for (const paramEl of paramElements) {
      if (paramEl) {
        parameters.push(this.parseParameter(paramEl));
      }
    }

    // Parse direct parameter (if present)
    let directParameter: SDEFParameter | undefined;
    if (cmd['direct-parameter']) {
      directParameter = this.parseParameter(cmd['direct-parameter'], true);
    }

    // Parse result type (if present)
    let result: SDEFType | undefined;
    if (cmd.result) {
      const typeAttr = cmd.result['@_type'];
      if (typeAttr) {
        result = this.parseType(typeAttr);
      }
    }

    return {
      name,
      code,
      description: cmd['@_description'],
      parameters,
      directParameter,
      result,
    };
  }

  /**
   * Parse parameter element
   *
   * Note: Direct parameters don't have name/code attributes
   */
  private parseParameter(param: any, isDirectParameter: boolean = false): SDEFParameter {
    const name = param['@_name'] || (isDirectParameter ? 'direct-parameter' : '');
    const code = param['@_code'] || (isDirectParameter ? '----' : ''); // Direct params use '----' code
    const typeAttr = param['@_type'];

    if (!isDirectParameter && (!name || !code)) {
      throw new Error('Parameter missing required "name" or "code" attribute');
    }

    if (!typeAttr) {
      throw new Error(`Parameter "${name}" missing required "type" attribute`);
    }

    if (!isDirectParameter) {
      this.validateFourCharCode(code, 'parameter', name);
    }

    return {
      name,
      code,
      type: this.parseType(typeAttr),
      description: param['@_description'],
      optional: param['@_optional'] === 'yes',
    };
  }

  /**
   * Parse class element
   */
  private parseClass(cls: any): SDEFClass {
    const name = cls['@_name'];
    const code = cls['@_code'];

    if (!name || !code) {
      throw new Error('Class missing required "name" or "code" attribute');
    }

    this.validateFourCharCode(code, 'class', name);

    // Parse properties
    const properties: SDEFProperty[] = [];
    const propElements = this.ensureArray(cls.property);
    for (const propEl of propElements) {
      if (propEl) {
        properties.push(this.parseProperty(propEl));
      }
    }

    // Parse elements
    const elements: SDEFElement[] = [];
    const elemElements = this.ensureArray(cls.element);
    for (const elemEl of elemElements) {
      if (elemEl) {
        elements.push(this.parseElement(elemEl));
      }
    }

    return {
      name,
      code,
      description: cls['@_description'],
      properties,
      elements,
    };
  }

  /**
   * Parse property element
   */
  private parseProperty(prop: any): SDEFProperty {
    const name = prop['@_name'];
    const code = prop['@_code'];
    const typeAttr = prop['@_type'];

    if (!name || !code) {
      throw new Error('Property missing required "name" or "code" attribute');
    }

    if (!typeAttr) {
      throw new Error(`Property "${name}" missing required "type" attribute`);
    }

    this.validateFourCharCode(code, 'property', name);

    // Parse access (default to read-write if not specified)
    let access: 'r' | 'w' | 'rw' = 'rw';
    if (prop['@_access']) {
      const accessValue = prop['@_access'];
      if (accessValue === 'r' || accessValue === 'w' || accessValue === 'rw') {
        access = accessValue;
      } else {
        throw new Error(`Invalid access value "${accessValue}" for property "${name}"`);
      }
    }

    return {
      name,
      code,
      type: this.parseType(typeAttr),
      description: prop['@_description'],
      access,
    };
  }

  /**
   * Parse element (child object reference)
   */
  private parseElement(elem: any): SDEFElement {
    const type = elem['@_type'];

    if (!type) {
      throw new Error('Element missing required "type" attribute');
    }

    // Parse access (default to read-only for elements)
    let access: 'r' | 'w' | 'rw' = 'r';
    if (elem['@_access']) {
      const accessValue = elem['@_access'];
      if (accessValue === 'r' || accessValue === 'w' || accessValue === 'rw') {
        access = accessValue;
      }
    }

    return {
      type,
      access,
    };
  }

  /**
   * Parse enumeration element
   */
  private parseEnumeration(enumEl: any): SDEFEnumeration {
    const name = enumEl['@_name'];
    const code = enumEl['@_code'];

    if (!name || !code) {
      throw new Error('Enumeration missing required "name" or "code" attribute');
    }

    this.validateFourCharCode(code, 'enumeration', name);

    // Parse enumerators
    const enumerators: SDEFEnumerator[] = [];
    const enumeratorElements = this.ensureArray(enumEl.enumerator);
    for (const enumrEl of enumeratorElements) {
      if (enumrEl) {
        enumerators.push(this.parseEnumerator(enumrEl));
      }
    }

    return {
      name,
      code,
      enumerators,
    };
  }

  /**
   * Parse enumerator element
   */
  private parseEnumerator(enumr: any): SDEFEnumerator {
    const name = enumr['@_name'];
    const code = enumr['@_code'];

    if (!name || !code) {
      throw new Error('Enumerator missing required "name" or "code" attribute');
    }

    this.validateFourCharCode(code, 'enumerator', name);

    return {
      name,
      code,
      description: enumr['@_description'],
    };
  }

  /**
   * Parse type string into SDEFType
   *
   * Handles:
   * - Primitive types: text, integer, real, boolean
   * - File types: file, alias
   * - List types: "list of X"
   * - Record types: record
   * - Class references
   * - Enumeration references
   */
  private parseType(typeStr: string): SDEFType {
    // Trim whitespace
    typeStr = typeStr.trim();

    // Handle primitive types
    if (typeStr === 'text' || typeStr === 'string') {
      return { kind: 'primitive', type: 'text' };
    }
    if (typeStr === 'integer' || typeStr === 'number') {
      return { kind: 'primitive', type: 'integer' };
    }
    if (typeStr === 'real' || typeStr === 'double') {
      return { kind: 'primitive', type: 'real' };
    }
    if (typeStr === 'boolean') {
      return { kind: 'primitive', type: 'boolean' };
    }

    // Handle file types
    if (typeStr === 'file' || typeStr === 'alias') {
      return { kind: 'file' };
    }

    // Handle list types: "list of X"
    const listMatch = typeStr.match(/^list(?:\s+of\s+(.+))?$/i);
    if (listMatch) {
      const itemTypeStr = listMatch[1];
      if (itemTypeStr) {
        return {
          kind: 'list',
          itemType: this.parseType(itemTypeStr),
        };
      }
      // Generic list without specified item type - default to text
      return {
        kind: 'list',
        itemType: { kind: 'primitive', type: 'text' },
      };
    }

    // Handle record types
    if (typeStr === 'record') {
      return {
        kind: 'record',
        properties: {}, // Properties would be defined elsewhere in SDEF
      };
    }

    // Check if it's an enumeration reference (common pattern: ends with 'enum' or starts with capital)
    // This is a heuristic - we'll treat any unknown type as potentially a class or enum reference
    // In a real implementation, we'd cross-reference with known classes/enums

    // For now, assume unknown types are class references
    // A more sophisticated implementation would check against parsed classes/enums
    return {
      kind: 'class',
      className: typeStr,
    };
  }

  /**
   * Validate four-character code format
   *
   * Note: Commands use 8-character codes (two 4-char codes combined),
   * while other elements use 4-character codes
   */
  private validateFourCharCode(code: string, elementType: string, elementName: string): void {
    // Commands can have 8-character codes (e.g., "aevtodoc" = "aevt" + "odoc")
    // Other elements have 4-character codes
    const validLength = elementType === 'command' ? 8 : 4;

    if (code.length !== validLength) {
      throw new Error(
        `Invalid code "${code}" for ${elementType} "${elementName}": must be exactly ${validLength} characters`
      );
    }

    // Codes should be ASCII printable characters
    for (let i = 0; i < code.length; i++) {
      const charCode = code.charCodeAt(i);
      if (charCode < 32 || charCode > 126) {
        throw new Error(
          `Invalid code "${code}" for ${elementType} "${elementName}": contains non-printable character`
        );
      }
    }
  }

  /**
   * Ensure value is an array (XML parser returns single item or array)
   */
  private ensureArray<T>(value: T | T[] | undefined): T[] {
    if (value === undefined || value === null) {
      return [];
    }
    return Array.isArray(value) ? value : [value];
  }

  /**
   * Clear the parse cache (useful for testing)
   */
  clearCache(): void {
    this.parseCache.clear();
  }
}

/**
 * Singleton instance for convenience
 */
export const sdefParser = new SDEFParser();
