/**
 * SDEF XML Parser
 *
 * Parses macOS SDEF (Scripting Definition) XML files and extracts
 * structured data about application capabilities.
 */

import { readFile, stat } from 'fs/promises';
import { XMLParser } from 'fast-xml-parser';
import { EntityResolver } from './entity-resolver.js';
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
 * Maximum allowed SDEF file size (10MB)
 * Prevents XML billion laughs and other DoS attacks
 */
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB

/**
 * Warning emitted during parsing when type inference occurs
 */
export interface ParseWarning {
  /** Warning code (e.g., 'MISSING_TYPE', 'UNION_TYPE_SIMPLIFIED') */
  code: string;
  /** Human-readable description */
  message: string;
  /** Location context for the warning */
  location: {
    /** Element type (e.g., 'parameter', 'property', 'direct-parameter', 'result') */
    element: string;
    /** Element name */
    name: string;
    /** Parent suite name (if applicable) */
    suite?: string;
    /** Parent command name (if applicable) */
    command?: string;
  };
  /** Value that was inferred (if applicable) */
  inferredValue?: string;
}

/**
 * Options for SDEF Parser configuration
 */
export interface SDEFParserOptions {
  /**
   * Parsing mode - strict or lenient
   * - strict: Throw error on missing types
   * - lenient: Infer types and emit warnings
   * Default: 'lenient'
   */
  mode?: 'strict' | 'lenient';

  /**
   * @deprecated Use mode: 'strict' instead
   * Enable strict type checking - throw error on unknown types
   */
  strictTypeChecking?: boolean;

  /**
   * Callback for warnings during parsing
   */
  onWarning?: (warning: ParseWarning) => void;
}

/**
 * Mapping from four-character codes to type strings
 * Based on Apple Event Manager constants
 */
const CODE_TO_TYPE_MAP: Record<string, string> = {
  kfil: 'file', // File parameter
  insh: 'location specifier', // Insertion location
  savo: 'save options', // Save options enum
  kocl: 'type', // Class/type reference
  prdt: 'record', // Properties record
  usin: 'specifier', // Using parameter
  rtyp: 'type', // Return type
  faal: 'list', // Modifier flags list
  data: 'any', // Generic data
};

/**
 * Mapping from standard parameter names to types
 */
const STANDARD_PARAM_TYPES: Record<string, string> = {
  in: 'file',
  to: 'location specifier',
  using: 'specifier',
  'with properties': 'record',
  each: 'type',
  as: 'type',
  saving: 'save options',
  by: 'property',
};

/**
 * SDEF Parser - extracts structured data from SDEF XML files
 */
export class SDEFParser {
  private parser: XMLParser;
  private parseCache: Map<string, SDEFDictionary>;
  private readonly MAX_CACHE_SIZE = 50; // Limit cache entries
  private readonly mode: 'strict' | 'lenient';
  private readonly onWarning?: (warning: ParseWarning) => void;
  private currentSuite?: string;
  private currentCommand?: string;
  private entityResolver?: EntityResolver;

  constructor(options?: SDEFParserOptions) {
    // Support deprecated strictTypeChecking option
    if (options?.strictTypeChecking !== undefined) {
      this.mode = options.strictTypeChecking ? 'strict' : 'lenient';
    } else {
      this.mode = options?.mode ?? 'lenient';
    }
    this.onWarning = options?.onWarning;
    // Configure XML parser
    this.parser = new XMLParser({
      ignoreAttributes: false,
      attributeNamePrefix: '@_',
      textNodeName: '#text',
      parseAttributeValue: false, // Keep as strings for type safety
      trimValues: false, // Don't trim - four-character codes may have trailing spaces
      // Security: Ignore XML declarations and processing instructions
      // to prevent XXE (XML External Entity) attacks
      ignoreDeclaration: true,
      ignorePiTags: true,
    });

    // Initialize entity resolver for safe XInclude/external entity resolution
    const additionalPaths: string[] = [];
    if (process.env.HOME) {
      additionalPaths.push(`${process.env.HOME}/Library/`);
    }

    this.entityResolver = new EntityResolver({
      additionalTrustedPaths: additionalPaths,
      maxDepth: 3,
      maxFileSize: 1024 * 1024, // 1MB per file
      maxTotalBytes: 10 * 1024 * 1024, // 10MB total
      maxIncludesPerFile: 50,
      debug: false,
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
      // Move to end for true LRU (most recently used)
      this.parseCache.delete(sdefPath);
      this.parseCache.set(sdefPath, cached);
      return cached;
    }

    try {
      // Security: Check file size to prevent DoS attacks
      const stats = await stat(sdefPath);
      if (stats.size > MAX_FILE_SIZE) {
        throw new Error(
          `SDEF file too large: ${stats.size} bytes (max ${MAX_FILE_SIZE} bytes)`
        );
      }

      let xmlContent = await readFile(sdefPath, 'utf-8');

      // SECURITY: Resolve external entities (XInclude) before parsing
      // This enables support for Pages, Numbers, Keynote, and System Events SDEF files
      // that use xi:include to reference shared definitions
      try {
        if (this.entityResolver) {
          xmlContent = await this.entityResolver.resolveIncludes(xmlContent, sdefPath);
        }
      } catch (resolverError) {
        // Log entity resolution errors but continue parsing
        // The parser will handle malformed XML or unresolved entities gracefully
        if (this.onWarning) {
          this.onWarning({
            code: 'ENTITY_RESOLUTION_ERROR',
            message: `Failed to resolve external entities: ${resolverError instanceof Error ? resolverError.message : String(resolverError)}`,
            location: {
              element: 'document',
              name: sdefPath,
              suite: undefined,
              command: undefined,
            },
          });
        }
      }

      const result = await this.parseContent(xmlContent);

      // Cache the result with LRU eviction
      if (this.parseCache.size >= this.MAX_CACHE_SIZE) {
        // Evict oldest entry (first key in Map)
        const firstKey = this.parseCache.keys().next().value;
        if (firstKey) {
          this.parseCache.delete(firstKey);
        }
      }
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

    // Track current suite for warning context
    this.currentSuite = name;

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

    // Track current command for warning context
    this.currentCommand = name;

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
    if ('direct-parameter' in cmd) {
      // Empty elements parse as empty strings, so create empty object if needed
      const directParamEl = cmd['direct-parameter'] || {};
      directParameter = this.parseParameter(directParamEl, true);
    }

    // Parse result type (if present)
    let result: SDEFType | undefined;
    if ('result' in cmd) {
      // Empty elements parse as empty strings, so create empty object if needed
      const resultEl = cmd.result || {};
      const typeAttr = resultEl['@_type'];
      const childTypes = resultEl.type;

      if (typeAttr) {
        result = this.parseType(typeAttr);
      } else if (childTypes) {
        result = this.inferTypeFromElement(resultEl, 'result', 'result');
      } else if (this.mode === 'lenient') {
        // Infer type for result (will emit MISSING_TYPE warning)
        result = this.inferType('result', undefined, 'result');
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
    const childTypes = param.type;

    // Only validate non-empty names and codes (lenient mode allows empty names in edge cases)
    if (!isDirectParameter && !code) {
      throw new Error('Parameter missing required "code" attribute');
    }

    if (!isDirectParameter && code) {
      this.validateFourCharCode(code, 'parameter', name || 'unnamed');
    }

    // Determine parameter type with priority order:
    // 1. Child <type> elements (PRIORITY 1 - EXPLICIT)
    // 2. type attribute (PRIORITY 1 - EXPLICIT)
    // 3. Inference in lenient mode
    let type: SDEFType;

    if (childTypes) {
      // Child type elements take priority
      type = this.inferTypeFromElement(
        param,
        isDirectParameter ? 'direct-parameter' : 'parameter',
        name
      );
    } else if (typeAttr) {
      // Explicit type attribute
      type = this.parseType(typeAttr);
    } else if (this.mode === 'strict') {
      // Strict mode - throw error
      throw new Error(`Parameter "${name}" missing required "type" attribute`);
    } else {
      // Lenient mode - infer type
      const context = isDirectParameter ? 'direct-parameter' : 'parameter';
      type = this.inferType(name, code, context);
    }

    return {
      name,
      code,
      type,
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
    const childTypes = prop.type;

    if (!name || !code) {
      throw new Error('Property missing required "name" or "code" attribute');
    }

    this.validateFourCharCode(code, 'property', name);

    // Determine property type
    let type: SDEFType;

    if (childTypes) {
      type = this.inferTypeFromElement(prop, 'property', name);
    } else if (typeAttr) {
      type = this.parseType(typeAttr);
    } else if (this.mode === 'strict') {
      throw new Error(`Property "${name}" missing required "type" attribute`);
    } else {
      // Lenient mode - infer type
      type = this.inferType(name, code, 'property');
    }

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
      type,
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
   * Emit a warning during parsing
   */
  private warn(warning: ParseWarning): void {
    if (this.onWarning) {
      this.onWarning(warning);
    }
  }

  /**
   * Infer type from child <type> elements
   */
  private inferTypeFromElement(
    element: any,
    elementType: string,
    elementName: string
  ): SDEFType {
    const types = this.ensureArray(element.type);

    if (types.length === 0) {
      // No child types - fall back to inference
      return this.inferType(elementName, element['@_code'], elementType as any);
    }

    if (types.length === 1) {
      // Single type - parse it
      const typeAttr = types[0]['@_type'];
      if (typeAttr) {
        return this.parseType(typeAttr);
      }
    }

    // Multiple types - union type (not fully supported yet)
    // Use first type and warn
    const firstType = types[0]['@_type'];
    if (firstType) {
      this.warn({
        code: 'UNION_TYPE_SIMPLIFIED',
        message: `Element has multiple type options, using first type: ${firstType}`,
        location: {
          element: elementType,
          name: elementName,
          suite: this.currentSuite,
          command: this.currentCommand,
        },
        inferredValue: firstType,
      });
      return this.parseType(firstType);
    }

    // Fallback
    return { kind: 'any' };
  }

  /**
   * Infer type when explicit type is missing
   *
   * Priority order:
   * 1. Four-character code mapping (PRIORITY 2)
   * 2. Standard parameter name patterns (PRIORITY 3)
   * 3. Substring patterns (PRIORITY 4)
   * 4. Context-aware defaults (PRIORITY 5)
   */
  private inferType(
    elementName: string,
    elementCode?: string,
    context?: 'parameter' | 'property' | 'direct-parameter' | 'result'
  ): SDEFType {
    let inferredType: SDEFType | null = null;

    // Always emit MISSING_TYPE warning first
    this.warn({
      code: 'MISSING_TYPE',
      message: 'Type attribute missing, inferring from context',
      location: {
        element: context || 'unknown',
        name: elementName,
        suite: this.currentSuite,
        command: this.currentCommand,
      },
    });

    // PRIORITY 2: Four-character code mapping
    if (elementCode) {
      const trimmedCode = elementCode.trim();
      const mappedType = CODE_TO_TYPE_MAP[trimmedCode];
      if (mappedType) {
        inferredType = this.parseType(mappedType);

        this.warn({
          code: 'TYPE_INFERRED_FROM_CODE',
          message: `Type inferred from four-character code "${trimmedCode}": ${mappedType}`,
          location: {
            element: context || 'unknown',
            name: elementName,
            suite: this.currentSuite,
            command: this.currentCommand,
          },
          inferredValue: mappedType,
        });

        return inferredType;
      }
    }

    // PRIORITY 3: Standard parameter name patterns
    const trimmedName = elementName.trim();
    const standardType = STANDARD_PARAM_TYPES[trimmedName];
    if (standardType) {
      inferredType = this.parseType(standardType);

      this.warn({
        code: 'TYPE_INFERRED_FROM_NAME',
        message: `Type inferred from parameter name "${elementName}": ${standardType}`,
        location: {
          element: context || 'unknown',
          name: elementName,
          suite: this.currentSuite,
          command: this.currentCommand,
        },
        inferredValue: standardType,
      });

      return inferredType;
    }

    // PRIORITY 4: Substring patterns (heuristics)
    const lowerName = elementName.toLowerCase();

    // File-related
    if (
      lowerName.includes('path') ||
      lowerName.includes('file') ||
      lowerName.includes('folder') ||
      lowerName.includes('directory')
    ) {
      inferredType = { kind: 'file' };

      this.warn({
        code: 'TYPE_INFERRED_FROM_PATTERN',
        message: `Type inferred from name pattern "${elementName}": file`,
        location: {
          element: context || 'unknown',
          name: elementName,
          suite: this.currentSuite,
          command: this.currentCommand,
        },
        inferredValue: 'file',
      });

      return inferredType;
    }

    // Integer-related
    if (
      lowerName.includes('count') ||
      lowerName.includes('index') ||
      lowerName.includes('number') ||
      lowerName.includes('size')
    ) {
      inferredType = { kind: 'primitive', type: 'integer' };

      this.warn({
        code: 'TYPE_INFERRED_FROM_PATTERN',
        message: `Type inferred from name pattern "${elementName}": integer`,
        location: {
          element: context || 'unknown',
          name: elementName,
          suite: this.currentSuite,
          command: this.currentCommand,
        },
        inferredValue: 'integer',
      });

      return inferredType;
    }

    // Boolean-related
    if (
      lowerName.includes('enabled') ||
      lowerName.includes('disabled') ||
      lowerName.includes('visible') ||
      lowerName.includes('is')
    ) {
      inferredType = { kind: 'primitive', type: 'boolean' };

      this.warn({
        code: 'TYPE_INFERRED_FROM_PATTERN',
        message: `Type inferred from name pattern "${elementName}": boolean`,
        location: {
          element: context || 'unknown',
          name: elementName,
          suite: this.currentSuite,
          command: this.currentCommand,
        },
        inferredValue: 'boolean',
      });

      return inferredType;
    }

    // PRIORITY 5: Context-aware defaults
    let defaultType: SDEFType;
    let defaultTypeStr: string;

    if (context === 'direct-parameter' || context === 'result') {
      defaultType = { kind: 'any' };
      defaultTypeStr = 'any';
    } else {
      defaultType = { kind: 'primitive', type: 'text' };
      defaultTypeStr = 'text';
    }

    // Emit additional warning for default fallback
    this.warn({
      code: 'TYPE_INFERRED_DEFAULT',
      message: `No specific type pattern matched, defaulting to "${defaultTypeStr}"`,
      location: {
        element: context || 'unknown',
        name: elementName,
        suite: this.currentSuite,
        command: this.currentCommand,
      },
      inferredValue: defaultTypeStr,
    });

    return defaultType;
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
   * - macOS-specific types: missing value, type, location specifier, color, date
   */
  private parseType(typeStr: string): SDEFType {
    // Safe to trim type strings - four-character codes only appear in 'code' attributes
    // Type attributes contain strings like "text", "list of file", etc.
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

    // Handle macOS-specific types
    if (typeStr === 'any') {
      return { kind: 'any' };
    }
    if (typeStr === 'missing value') {
      return { kind: 'missing_value' };
    }
    if (typeStr === 'type') {
      return { kind: 'type_class' };
    }
    if (typeStr === 'location specifier' || typeStr === 'specifier') {
      return { kind: 'location_specifier' };
    }
    if (typeStr === 'color') {
      return { kind: 'color' };
    }
    if (typeStr === 'date') {
      return { kind: 'date' };
    }
    if (typeStr === 'property') {
      return { kind: 'property' };
    }
    if (typeStr === 'save options') {
      return { kind: 'save_options' };
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

    // Unknown type handling
    if (this.mode === 'strict') {
      throw new Error(`Unknown type: "${typeStr}"`);
    }

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

    // Codes should be ASCII printable characters (no null bytes or control chars)
    for (let i = 0; i < code.length; i++) {
      const charCode = code.charCodeAt(i);
      if (charCode === 0 || charCode < 32 || charCode > 126) {
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
