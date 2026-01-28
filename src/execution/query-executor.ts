import { ObjectReference } from "../types/object-reference.js";
import {
  ObjectSpecifier,
  isElementSpecifier,
  isNamedSpecifier,
  isIdSpecifier,
  isPropertySpecifier,
  ElementSpecifier
} from "../types/object-specifier.js";
import { ReferenceStore } from "./reference-store.js";
import { JXAExecutor } from "../adapters/macos/jxa-executor.js";
import { ResultParser, JXAError } from "../adapters/macos/result-parser.js";

/**
 * Regex for validating JXA-safe identifiers.
 * Allows alphanumeric characters, regular spaces (0x20), hyphens, and underscores.
 * Explicitly excludes other whitespace characters like \t, \n, \r that could be used for injection.
 * This prevents code injection when building JXA path strings.
 */
const SAFE_IDENTIFIER_REGEX = /^[a-zA-Z0-9_ \-]+$/;

/**
 * Regex for validating application names.
 * More permissive than SAFE_IDENTIFIER_REGEX to allow dots in bundle IDs.
 * Examples: "Mail", "com.apple.finder", "Microsoft Word"
 */
const SAFE_APP_NAME_REGEX = /^[a-zA-Z0-9_.\- ]+$/;

/**
 * Maximum length for identifier strings to prevent DoS attacks.
 */
const MAX_IDENTIFIER_LENGTH = 256;

/**
 * Executes queries against applications and manages object references.
 * Builds JXA code from ObjectSpecifier types and executes queries.
 */
export class QueryExecutor {
  private resultParser: ResultParser;

  /**
   * Create a new QueryExecutor.
   *
   * @param referenceStore - Store for managing object references
   * @param jxaExecutor - Optional JXAExecutor for real JXA execution.
   *                      If not provided, methods return empty/mock results.
   */
  constructor(
    private referenceStore: ReferenceStore,
    private jxaExecutor?: JXAExecutor
  ) {
    this.resultParser = new ResultParser();
  }

  /**
   * Query an object and return a reference.
   *
   * @param app - The application name (e.g., "Mail")
   * @param specifier - The object specifier to resolve
   * @returns A reference to the resolved object
   */
  async queryObject(
    app: string,
    specifier: ObjectSpecifier
  ): Promise<ObjectReference> {
    // 0. Validate app name for JXA safety (prevent injection attacks)
    this.validateAppName(app);
    // 0a. Validate specifier type
    this.validateSpecifier(specifier);
    // 0b. Validate specifier values for JXA safety (prevent injection attacks)
    this.validateSpecifierValues(specifier);

    // 1. Build JXA code to resolve specifier
    // const jxaCode = this.buildObjectPath(specifier, `Application("${app}")`);

    // 2. Execute JXA (for Phase 1, we mock this - will integrate actual execution in Task 5)
    // In production, this would call the JXA executor
    // const result = await this.jxaExecutor.execute(app, jxaCode);

    // 3. Extract object type from specifier
    const objectType = this.extractObjectType(specifier);

    // 4. Create reference in store
    const referenceId = this.referenceStore.create(app, objectType, specifier);

    // 5. Return reference
    const reference = this.referenceStore.get(referenceId);
    if (!reference) {
      throw new Error('Failed to create reference');
    }
    return reference;
  }

  /**
   * Get properties of a referenced object.
   *
   * @param referenceId - The ID of the reference
   * @param properties - Optional array of property names to retrieve
   * @returns Record of property names to values
   */
  async getProperties(
    referenceId: string,
    properties?: string[]
  ): Promise<Record<string, any>> {
    // 1. Get reference from store
    const reference = this.referenceStore.get(referenceId);
    if (!reference) {
      throw new Error(`Reference not found: ${referenceId}`);
    }

    // 2. Touch reference (update lastAccessedAt)
    this.referenceStore.touch(referenceId);

    // 3. If no JXAExecutor, return empty result (backward compatibility)
    if (!this.jxaExecutor) {
      return {};
    }

    // 4. Build JXA to get properties
    const objectPath = this.buildObjectPath(reference.specifier, "app");
    let jxaCode: string;

    if (properties && properties.length > 0) {
      // Get specific properties
      const propertyAccess = properties.map(prop =>
        `${this.camelCase(prop)}: obj.${this.camelCase(prop)}()`
      ).join(', ');
      jxaCode = `(() => {
  const app = Application("${this.escapeJxaString(reference.app)}");
  const obj = ${objectPath};
  return JSON.stringify({ ${propertyAccess} });
})()`;
    } else {
      // Get all properties
      jxaCode = `(() => {
  const app = Application("${this.escapeJxaString(reference.app)}");
  const obj = ${objectPath};
  return JSON.stringify(obj.properties());
})()`;
    }

    // 5. Execute JXA
    const result = await this.jxaExecutor.execute(jxaCode);

    // 6. Parse result and handle errors
    const parsed = this.resultParser.parse(result, { appName: reference.app });

    if (!parsed.success) {
      throw new Error(this.formatJxaError(parsed.error!));
    }

    return parsed.data || {};
  }

  /**
   * Get elements from a container.
   *
   * @param container - Reference ID or ObjectSpecifier
   * @param elementType - Type of elements to retrieve
   * @param app - Application name (required when container is ObjectSpecifier)
   * @param limit - Maximum number of elements to return (default: 100)
   * @returns Elements with metadata
   */
  async getElements(
    container: string | ObjectSpecifier,
    elementType: string,
    app?: string,
    limit: number = 100
  ): Promise<{ elements: ObjectReference[]; count: number; hasMore: boolean }> {
    // 1. Resolve container (reference ID or specifier)
    let containerSpec: ObjectSpecifier;
    let resolvedApp: string;

    if (typeof container === 'string') {
      // It's a reference ID
      const reference = this.referenceStore.get(container);
      if (!reference) {
        throw new Error(`Reference not found: ${container}`);
      }
      containerSpec = reference.specifier;
      resolvedApp = reference.app;
    } else {
      // It's a specifier - app is required
      if (!app) {
        throw new Error('App parameter is required when container is an ObjectSpecifier');
      }
      containerSpec = container;
      resolvedApp = app;
    }

    // 2. If no JXAExecutor, return empty result (backward compatibility)
    if (!this.jxaExecutor) {
      return this.mockExecuteGetElementsResult(resolvedApp, containerSpec, elementType, limit);
    }

    // 3. Validate element type for JXA safety
    this.sanitizeForJxa(elementType, 'elementType');

    // 4. Build JXA to get elements
    const containerPath = this.buildObjectPath(containerSpec, "app");
    const pluralElementType = this.pluralize(elementType);

    const jxaCode = `(() => {
  const app = Application("${this.escapeJxaString(resolvedApp)}");
  const container = ${containerPath};
  const elements = container.${pluralElementType};
  const count = elements.length;
  const items = [];
  for (let i = 0; i < Math.min(count, ${limit}); i++) {
    items.push({ index: i });
  }
  return JSON.stringify({ count, items });
})()`;

    // 5. Execute JXA
    const result = await this.jxaExecutor.execute(jxaCode);

    // 6. Parse result and handle errors
    const parsed = this.resultParser.parse(result, { appName: resolvedApp });

    if (!parsed.success) {
      throw new Error(this.formatJxaError(parsed.error!));
    }

    const jxaResult = parsed.data || { count: 0, items: [] };

    // 7. Create references for each element
    const elements: ObjectReference[] = jxaResult.items.map((_item: any, index: number) => {
      const elementSpec: ElementSpecifier = {
        type: 'element',
        element: elementType,
        index,
        container: containerSpec
      };

      const referenceId = this.referenceStore.create(resolvedApp, elementType, elementSpec);
      const reference = this.referenceStore.get(referenceId);
      if (!reference) {
        throw new Error('Failed to create element reference');
      }
      return reference;
    });

    // 8. Return elements with metadata
    return {
      elements,
      count: jxaResult.count,
      hasMore: jxaResult.count > limit
    };
  }

  /**
   * Format a JXA error into a user-friendly message.
   *
   * @param error - The JXA error object
   * @returns Formatted error message
   */
  private formatJxaError(error: JXAError): string {
    switch (error.type) {
      case 'APP_NOT_FOUND':
        return 'Application not found or not installed';
      case 'APP_NOT_RUNNING':
        return 'Application is not running';
      case 'PERMISSION_DENIED':
        return 'Permission denied. Grant automation access in System Preferences > Privacy & Security > Automation.';
      case 'INVALID_PARAM':
        return 'Object not found: The specified element does not exist';
      case 'TIMEOUT':
        return 'Operation timed out';
      default:
        return error.message || 'JXA execution error';
    }
  }

  /**
   * Return mock/empty result for getElements when no JXAExecutor is provided.
   * Maintains backward compatibility with existing tests.
   */
  private async mockExecuteGetElementsResult(
    resolvedApp: string,
    containerSpec: ObjectSpecifier,
    elementType: string,
    limit: number
  ): Promise<{ elements: ObjectReference[]; count: number; hasMore: boolean }> {
    const mockResult = this.mockExecuteGetElements(resolvedApp, containerSpec, elementType, limit);

    // Create references for each element (preserves existing test behavior)
    const elements: ObjectReference[] = mockResult.items.map((_item: any, index: number) => {
      const elementSpec: ElementSpecifier = {
        type: 'element',
        element: elementType,
        index,
        container: containerSpec
      };

      const referenceId = this.referenceStore.create(resolvedApp, elementType, elementSpec);
      const reference = this.referenceStore.get(referenceId);
      if (!reference) {
        throw new Error('Failed to create element reference');
      }
      return reference;
    });

    return {
      elements,
      count: mockResult.count,
      hasMore: mockResult.count > limit
    };
  }

  /**
   * Sanitize a string for safe use in JXA code generation.
   * Validates against injection attacks by checking:
   * 1. Length limits (prevents DoS)
   * 2. Character allowlist (prevents code injection)
   *
   * @param value - The string to sanitize
   * @param fieldName - Name of the field for error messages
   * @returns The sanitized string (unchanged if valid)
   * @throws Error if the string fails validation
   */
  private sanitizeForJxa(value: string, fieldName: string): string {
    // Length check
    if (value.length > MAX_IDENTIFIER_LENGTH) {
      throw new Error(`${fieldName} exceeds maximum length (${MAX_IDENTIFIER_LENGTH} characters)`);
    }

    // Character allowlist check
    if (!SAFE_IDENTIFIER_REGEX.test(value)) {
      throw new Error(`${fieldName} contains invalid characters. Only alphanumeric, spaces, hyphens, and underscores are allowed.`);
    }

    return value;
  }

  /**
   * Validate and sanitize application name parameter.
   * App names can contain dots (for bundle IDs like "com.apple.finder")
   * and other characters not allowed in specifier fields.
   *
   * @param app - The application name to validate
   * @throws Error if the app name is invalid or potentially malicious
   */
  private validateAppName(app: string): void {
    if (!app || typeof app !== 'string') {
      throw new Error('App name is required and must be a string');
    }

    if (app.length > MAX_IDENTIFIER_LENGTH) {
      throw new Error(`App name exceeds maximum length (${MAX_IDENTIFIER_LENGTH} characters)`);
    }

    if (!SAFE_APP_NAME_REGEX.test(app)) {
      throw new Error('App name contains invalid characters. Only alphanumeric, spaces, dots, hyphens, and underscores are allowed.');
    }
  }

  /**
   * Escape a string for safe inclusion in JXA code as a string literal.
   * This provides defense-in-depth even though the allowlist regex should
   * prevent dangerous characters from ever reaching this point.
   *
   * @param value - The string to escape
   * @returns The escaped string safe for JXA string interpolation
   */
  private escapeJxaString(value: string): string {
    return value
      .replace(/\\/g, '\\\\')  // Escape backslashes first
      .replace(/"/g, '\\"')     // Escape double quotes
      .replace(/'/g, "\\'")     // Escape single quotes
      .replace(/\n/g, '\\n')    // Escape newlines
      .replace(/\r/g, '\\r')    // Escape carriage returns
      .replace(/\t/g, '\\t');   // Escape tabs
  }

  /**
   * Build JXA object path from specifier.
   * This generates the correct JXA syntax for accessing objects.
   *
   * SECURITY: All user-provided strings (name, id, element, property) are
   * sanitized before being interpolated into JXA code to prevent injection attacks.
   *
   * @param specifier - The object specifier
   * @param appVar - The app variable name (default: "app")
   * @returns JXA path string
   */
  private buildObjectPath(specifier: ObjectSpecifier, appVar: string = "app"): string {
    if (isElementSpecifier(specifier)) {
      // Sanitize element name before interpolation
      const sanitizedElement = this.sanitizeForJxa(specifier.element, 'element');

      const containerPath = specifier.container === "application"
        ? appVar
        : this.buildObjectPath(specifier.container, appVar);
      // JXA: app.messages[0] or container.messages[index]
      // Note: index is a number, no sanitization needed
      return `${containerPath}.${this.pluralize(sanitizedElement)}[${specifier.index}]`;
    }

    if (isNamedSpecifier(specifier)) {
      // Sanitize both element and name before interpolation
      const sanitizedElement = this.sanitizeForJxa(specifier.element, 'element');
      const sanitizedName = this.sanitizeForJxa(specifier.name, 'name');

      const containerPath = specifier.container === "application"
        ? appVar
        : this.buildObjectPath(specifier.container, appVar);
      // JXA: app.mailboxes.byName("inbox")
      // Defense-in-depth: escape the name string even though sanitizeForJxa should prevent dangerous chars
      return `${containerPath}.${this.pluralize(sanitizedElement)}.byName("${this.escapeJxaString(sanitizedName)}")`;
    }

    if (isIdSpecifier(specifier)) {
      // Sanitize both element and id before interpolation
      const sanitizedElement = this.sanitizeForJxa(specifier.element, 'element');
      const sanitizedId = this.sanitizeForJxa(specifier.id, 'id');

      const containerPath = specifier.container === "application"
        ? appVar
        : this.buildObjectPath(specifier.container, appVar);
      // JXA: app.messages.byId("abc123")
      // Defense-in-depth: escape the id string even though sanitizeForJxa should prevent dangerous chars
      return `${containerPath}.${this.pluralize(sanitizedElement)}.byId("${this.escapeJxaString(sanitizedId)}")`;
    }

    if (isPropertySpecifier(specifier)) {
      // Sanitize property name before interpolation
      const sanitizedProperty = this.sanitizeForJxa(specifier.property, 'property');

      // Handle "of" being either reference ID or specifier
      const ofPath = typeof specifier.of === "string"
        ? this.resolveReferenceToPath(specifier.of)
        : this.buildObjectPath(specifier.of, appVar);
      // JXA: message.subject() or object.property()
      return `${ofPath}.${this.camelCase(sanitizedProperty)}()`;
    }

    throw new Error(`Unsupported specifier type: ${(specifier as any).type}`);
  }

  /**
   * Resolve a reference ID to a JXA path.
   *
   * @param referenceId - The reference ID
   * @returns JXA path string
   */
  private resolveReferenceToPath(referenceId: string): string {
    const ref = this.referenceStore.get(referenceId);
    if (!ref) {
      throw new Error(`Reference not found: ${referenceId}`);
    }
    return this.buildObjectPath(ref.specifier, `Application("${ref.app}")`);
  }

  /**
   * Validate that a specifier has a supported type and valid references.
   *
   * @param specifier - The object specifier to validate
   * @throws Error if specifier type is unsupported or references are invalid
   */
  private validateSpecifier(specifier: ObjectSpecifier): void {
    // Check if specifier has a recognized type
    if (!isElementSpecifier(specifier) &&
        !isNamedSpecifier(specifier) &&
        !isIdSpecifier(specifier) &&
        !isPropertySpecifier(specifier)) {
      throw new Error(`Unsupported specifier type: ${(specifier as any).type}`);
    }

    // For PropertySpecifier with reference ID, validate reference exists
    if (isPropertySpecifier(specifier) && typeof specifier.of === "string") {
      const ref = this.referenceStore.get(specifier.of);
      if (!ref) {
        throw new Error(`Reference not found: ${specifier.of}`);
      }
    }

    // Recursively validate nested specifiers
    if (isElementSpecifier(specifier) || isNamedSpecifier(specifier) || isIdSpecifier(specifier)) {
      if (specifier.container !== "application" && typeof specifier.container === "object") {
        this.validateSpecifier(specifier.container);
      }
    }

    if (isPropertySpecifier(specifier) && typeof specifier.of === "object") {
      this.validateSpecifier(specifier.of);
    }
  }

  /**
   * Validate specifier values for JXA safety.
   * This prevents code injection by ensuring all user-provided strings
   * match the allowed character pattern and are within length limits.
   *
   * @param specifier - The object specifier to validate
   * @throws Error if any value fails validation
   */
  private validateSpecifierValues(specifier: ObjectSpecifier): void {
    if (isElementSpecifier(specifier)) {
      this.sanitizeForJxa(specifier.element, 'element');
      if (specifier.container !== "application" && typeof specifier.container === "object") {
        this.validateSpecifierValues(specifier.container);
      }
    }

    if (isNamedSpecifier(specifier)) {
      this.sanitizeForJxa(specifier.element, 'element');
      this.sanitizeForJxa(specifier.name, 'name');
      if (specifier.container !== "application" && typeof specifier.container === "object") {
        this.validateSpecifierValues(specifier.container);
      }
    }

    if (isIdSpecifier(specifier)) {
      this.sanitizeForJxa(specifier.element, 'element');
      this.sanitizeForJxa(specifier.id, 'id');
      if (specifier.container !== "application" && typeof specifier.container === "object") {
        this.validateSpecifierValues(specifier.container);
      }
    }

    if (isPropertySpecifier(specifier)) {
      this.sanitizeForJxa(specifier.property, 'property');
      if (typeof specifier.of === "object") {
        this.validateSpecifierValues(specifier.of);
      }
    }
  }

  /**
   * Extract the object type from a specifier.
   *
   * @param specifier - The object specifier
   * @returns The object type
   */
  private extractObjectType(specifier: ObjectSpecifier): string {
    if (isElementSpecifier(specifier)) return specifier.element;
    if (isNamedSpecifier(specifier)) return specifier.element;
    if (isIdSpecifier(specifier)) return specifier.element;
    if (isPropertySpecifier(specifier)) {
      // For properties, extract type from "of"
      if (typeof specifier.of === "string") {
        const ref = this.referenceStore.get(specifier.of);
        return ref?.type || "unknown";
      }
      return this.extractObjectType(specifier.of);
    }
    return "unknown";
  }

  /**
   * Convert a property name to camelCase for JXA.
   *
   * @param str - The property name (e.g., "read status")
   * @returns Camel-cased property name (e.g., "readStatus")
   */
  private camelCase(str: string): string {
    return str.replace(/\s+(\w)/g, (_, char) => char.toUpperCase());
  }

  /**
   * Common irregular plurals found in macOS app scripting dictionaries.
   * Maps singular forms to their plural equivalents.
   */
  private static readonly IRREGULAR_PLURALS: Record<string, string> = {
    // Common English irregulars used in app scripting
    person: "people",
    child: "children",
    man: "men",
    woman: "women",
    foot: "feet",
    tooth: "teeth",
    goose: "geese",
    mouse: "mice",
    // macOS/app-specific terms
    index: "indices",
    appendix: "appendices",
    criterion: "criteria",
    datum: "data",
    medium: "media",
    // Words that are the same singular and plural
    series: "series",
    species: "species",
    deer: "deer",
    sheep: "sheep",
    fish: "fish",
    aircraft: "aircraft",
    // Common uncountable nouns often used in apps
    information: "information",
    software: "software",
    hardware: "hardware",
    data: "data",
    media: "media",
    // Words where final consonant doubles before 'es'
    quiz: "quizzes"
  };

  /**
   * Pluralize an element name for JXA collection access.
   *
   * This is a fallback pluralization method using common English rules.
   * Phase 5 will enhance this by extracting plural forms directly from
   * SDEF parsing, which will provide authoritative plural names for each
   * application's scripting dictionary.
   *
   * @param str - The element name (e.g., "message", "category", "person")
   * @returns Pluralized name (e.g., "messages", "categories", "people")
   */
  private pluralize(str: string): string {
    // Normalize to lowercase for lookup (preserve original for suffix rules)
    const lowerStr = str.toLowerCase();

    // 1. Check irregular plurals first
    if (QueryExecutor.IRREGULAR_PLURALS[lowerStr]) {
      return QueryExecutor.IRREGULAR_PLURALS[lowerStr];
    }

    // 2. Already plural (common patterns) - return as-is
    // Words ending in 'ies' (categories), 'es' (boxes), 's' (unless ending in 'ss')
    if (lowerStr.endsWith("ies") ||
        lowerStr.endsWith("ches") ||
        lowerStr.endsWith("shes") ||
        lowerStr.endsWith("xes") ||
        lowerStr.endsWith("zes") ||
        lowerStr.endsWith("ses") ||
        (lowerStr.endsWith("s") && !lowerStr.endsWith("ss") && lowerStr.length > 2)) {
      // Likely already plural - but be careful with words like "bus", "focus"
      // For safety, we only skip if it matches common plural patterns
      if (lowerStr.endsWith("ies") ||
          lowerStr.endsWith("ches") ||
          lowerStr.endsWith("shes") ||
          lowerStr.endsWith("xes") ||
          lowerStr.endsWith("zes")) {
        return str;
      }
    }

    // 3. Words ending in consonant + 'y' -> 'ies'
    // e.g., category -> categories, story -> stories
    if (lowerStr.endsWith("y") && lowerStr.length > 1) {
      const beforeY = lowerStr.charAt(lowerStr.length - 2);
      const vowels = "aeiou";
      if (beforeY && !vowels.includes(beforeY)) {
        return str.slice(0, -1) + "ies";
      }
    }

    // 4. Words ending in 's', 'ss', 'sh', 'ch', 'x' -> add 'es'
    // e.g., bus -> buses, class -> classes, box -> boxes
    if (lowerStr.endsWith("s") ||
        lowerStr.endsWith("ss") ||
        lowerStr.endsWith("sh") ||
        lowerStr.endsWith("ch") ||
        lowerStr.endsWith("x")) {
      return str + "es";
    }

    // 4a. Words ending in 'z' -> double the z and add 'es' (unless already 'zz')
    // e.g., quiz -> quizzes, but buzz -> buzzes (not buzzzes)
    if (lowerStr.endsWith("z") && !lowerStr.endsWith("zz")) {
      return str + "zes";
    }
    if (lowerStr.endsWith("zz")) {
      return str + "es";
    }

    // 5. Words ending in 'f' or 'fe' -> 'ves'
    // e.g., leaf -> leaves, knife -> knives
    // Note: Some exceptions like "roof" -> "roofs", but we'll handle common cases
    if (lowerStr.endsWith("fe")) {
      return str.slice(0, -2) + "ves";
    }
    if (lowerStr.endsWith("f") && !lowerStr.endsWith("ff")) {
      // Check for common exceptions that just add 's'
      const fExceptions = ["roof", "proof", "chief", "belief", "cliff", "cuff"];
      if (!fExceptions.includes(lowerStr)) {
        return str.slice(0, -1) + "ves";
      }
    }

    // 6. Words ending in 'o' - some add 'es', some add 's'
    // Common 'es' words: hero, potato, tomato, echo
    // Common 's' words: photo, piano, radio, video
    if (lowerStr.endsWith("o")) {
      const oAddEs = ["hero", "potato", "tomato", "echo", "veto", "embargo"];
      if (oAddEs.includes(lowerStr)) {
        return str + "es";
      }
      return str + "s";
    }

    // 7. Default: add 's'
    return str + "s";
  }

  /**
   * Mock implementation of getElements JXA execution.
   * This is a protected method to allow testing subclasses to override.
   * In Phase 5, this will be replaced with actual JXA execution.
   *
   * @protected
   */
  protected mockExecuteGetElements(
    _app: string,
    _containerSpec: ObjectSpecifier,
    _elementType: string,
    _limit: number
  ): { count: number; items: any[] } {
    return {
      count: 0,
      items: []
    };
  }
}
