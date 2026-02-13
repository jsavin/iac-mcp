import { ObjectReference } from "../types/object-reference.js";
import {
  ObjectSpecifier,
  isElementSpecifier,
  isNamedSpecifier,
  isIdSpecifier,
  isPropertySpecifier,
  isApplicationSpecifier,
  ElementSpecifier,
  PropertySpecifier
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
      throw new Error(`Reference not found: ${referenceId}. The referenced object may have been closed or deleted. Please re-query the object to get a fresh reference.`);
    }

    // 2. lastAccessedAt is auto-updated by get()

    // 3. If no JXAExecutor, return empty result (backward compatibility)
    if (!this.jxaExecutor) {
      return {};
    }

    // 4. Build JXA to get properties
    const objectPath = this.buildObjectPath(reference.specifier, "app");
    let jxaCode: string;

    if (properties && properties.length > 0) {
      // Get specific properties - sanitize each property name first to prevent injection
      // Each property is wrapped in a helper that detects arrays of JXA object specifiers
      // (e.g., selectedMessages) and serializes them as reference_list metadata instead of
      // attempting JSON.stringify (which produces [null] for object specifiers).
      const propertyAccess = properties.map(prop => {
        const sanitizedProp = this.sanitizeForJxa(prop, 'property');
        const camelProp = this.camelCase(sanitizedProp);
        // Defense-in-depth: escape camelProp even though sanitizeForJxa should prevent dangerous chars
        const escapedProp = this.escapeJxaString(camelProp);
        return this.buildPropertyAccessorIIFE(escapedProp, 'obj');
      }).join(', ');
      jxaCode = `(() => {
  const app = Application("${this.escapeJxaString(reference.app)}");
  const obj = ${objectPath};
  return JSON.stringify({ ${propertyAccess} });
})()`;
    } else {
      // Get all properties - try properties() first, fall back to reflection
      // Some apps (like Mail) don't support properties() and throw "AppleEvent handler failed"
      jxaCode = `(() => {
  const app = Application("${this.escapeJxaString(reference.app)}");
  const obj = ${objectPath};

  // Try the properties() method first (works for Finder, etc.)
  try {
    const props = obj.properties();
    if (props && typeof props === 'object') {
      const cleaned = {};
      const keys = Object.keys(props);
      for (const k of keys) {
        const v = props[k];
        if (v === null || v === undefined) {
          cleaned[k] = v;
        } else if (Array.isArray(v) && v.length > 0 && v.every(item => typeof item === 'object' && item !== null)) {
          cleaned[k] = { _type: 'reference_list', property: k, count: v.length, items: v.map((_, i) => ({ index: i })) };
        } else if (typeof v === 'object' && !Array.isArray(v)) {
          try {
            const str = JSON.stringify(v);
            if (str === undefined || str === 'null' || str === '{}') {
              cleaned[k] = { _type: 'object_reference', property: k };
            } else {
              cleaned[k] = v;
            }
          } catch(e) {
            cleaned[k] = { _type: 'object_reference', property: k };
          }
        } else {
          cleaned[k] = v;
        }
      }
      return JSON.stringify(cleaned);
    }
  } catch (e) {
    // properties() failed, fall back to reflection
  }

  // Fallback: Use Object.keys to discover available property accessors
  // In JXA, scriptable object properties are exposed as methods
  const result = {};
  const seen = new Set();

  // Walk the prototype chain to find all property accessors
  let proto = obj;
  while (proto && proto !== Object.prototype) {
    const names = Object.getOwnPropertyNames(proto);
    for (const name of names) {
      if (seen.has(name)) continue;
      seen.add(name);

      // Skip internal/system properties
      if (name.startsWith('_') || name === 'constructor') continue;

      // Try to call it as a property accessor (no arguments)
      try {
        const desc = Object.getOwnPropertyDescriptor(proto, name);
        if (desc && typeof desc.value === 'function') {
          // In JXA, property accessors are 0-arg functions
          const val = obj[name]();
          // Only include if it returns a primitive or simple object
          if (val !== undefined && val !== null) {
            const type = typeof val;
            if (type === 'string' || type === 'number' || type === 'boolean') {
              result[name] = val;
            } else if (val instanceof Date) {
              result[name] = val.toISOString();
            } else if (typeof val === 'object') {
              if (Array.isArray(val) && val.length > 0 && val.every(item => typeof item === 'object' && item !== null)) {
                result[name] = { _type: 'reference_list', property: name, count: val.length, items: val.map((_, i) => ({ index: i })) };
              } else if (!Array.isArray(val)) {
                result[name] = { _type: 'object_reference', property: name };
              }
            }
          }
        }
      } catch (e) {
        // This property accessor failed, skip it
      }
    }
    proto = Object.getPrototypeOf(proto);
  }

  return JSON.stringify(result);
})()`;
    }

    // 5. Execute JXA
    const jxaResult = await this.jxaExecutor.execute(jxaCode);

    // 6. Parse result and handle errors
    const parsed = this.resultParser.parse(jxaResult, { appName: reference.app });

    if (!parsed.success) {
      throw new Error(this.formatJxaError(parsed.error!));
    }

    const propertiesResult: Record<string, any> = parsed.data || {};

    // Post-process: convert reference markers into actual stored references
    for (const key of Object.keys(propertiesResult)) {
      const val = propertiesResult[key];
      if (val && typeof val === 'object') {
        if (val._type === 'reference_list' &&
            typeof val.property === 'string' &&
            typeof val.count === 'number' && Number.isInteger(val.count) && val.count >= 0) {
          propertiesResult[key] = this.createPropertyListReferences(
            reference.app,
            reference.specifier,
            val.property,
            val.count
          );
        } else if (val._type === 'object_reference' && typeof val.property === 'string') {
          propertiesResult[key] = this.createPropertyReference(
            reference.app,
            reference.specifier,
            val.property
          );
        }
      }
    }

    return propertiesResult;
  }

  /**
   * Set a property value on a referenced object.
   *
   * @param referenceId - The ID of the reference
   * @param property - The property name to set
   * @param value - The new value for the property
   */
  async setProperty(
    referenceId: string,
    property: string,
    value: unknown
  ): Promise<void> {
    // 1. Get reference from store
    const reference = this.referenceStore.get(referenceId);
    if (!reference) {
      throw new Error(`Reference not found: ${referenceId}. The referenced object may have been closed or deleted. Please re-query the object to get a fresh reference.`);
    }

    // 2. lastAccessedAt is auto-updated by get()

    // 3. If no JXAExecutor, throw error (can't set properties without execution)
    if (!this.jxaExecutor) {
      throw new Error('Cannot set property: JXA execution is not available');
    }

    // 4. Sanitize property name for JXA safety
    const sanitizedProp = this.sanitizeForJxa(property, 'property');
    const camelProp = this.camelCase(sanitizedProp);

    // 5. Serialize value for JXA
    const serializedValue = this.serializeValueForJxa(value);

    // 6. Build JXA to set property
    const objectPath = this.buildObjectPath(reference.specifier, "app");
    const jxaCode = `(() => {
  const app = Application("${this.escapeJxaString(reference.app)}");
  const obj = ${objectPath};
  obj.${camelProp} = ${serializedValue};
  return JSON.stringify({ success: true });
})()`;

    // 7. Execute JXA
    const result = await this.jxaExecutor.execute(jxaCode);

    // 8. Parse result and handle errors
    const parsed = this.resultParser.parse(result, { appName: reference.app });

    if (!parsed.success) {
      throw new Error(this.formatJxaError(parsed.error!));
    }
  }

  /**
   * Serialize a JavaScript value for use in JXA code.
   * Handles strings, numbers, booleans, null, and simple objects.
   *
   * @param value - The value to serialize
   * @returns JXA code representation of the value
   */
  private serializeValueForJxa(value: unknown): string {
    if (value === null) {
      return 'null';
    }
    if (value === undefined) {
      return 'undefined';
    }
    if (typeof value === 'string') {
      // Escape string for JXA
      return JSON.stringify(value);
    }
    if (typeof value === 'number') {
      if (!Number.isFinite(value)) {
        throw new Error(`Invalid number value: ${value}`);
      }
      return String(value);
    }
    if (typeof value === 'boolean') {
      return value ? 'true' : 'false';
    }
    if (value instanceof Date) {
      return `new Date("${value.toISOString()}")`;
    }
    if (Array.isArray(value)) {
      // Serialize array elements
      const elements = value.map(v => this.serializeValueForJxa(v));
      return `[${elements.join(', ')}]`;
    }
    if (typeof value === 'object') {
      // Serialize simple objects
      const entries = Object.entries(value).map(([k, v]) => {
        const sanitizedKey = this.sanitizeForJxa(k, 'key');
        return `${JSON.stringify(sanitizedKey)}: ${this.serializeValueForJxa(v)}`;
      });
      return `{${entries.join(', ')}}`;
    }
    throw new Error(`Cannot serialize value of type ${typeof value} for JXA`);
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
        throw new Error(`Reference not found: ${container}. The referenced object may have been closed or deleted. Please re-query the object to get a fresh reference.`);
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

    // 2. Validate element type for JXA safety FIRST (before any code paths use it)
    this.sanitizeForJxa(elementType, 'elementType');

    // 3. Validate limit parameter
    if (!Number.isInteger(limit) || limit < 0 || limit > 10000) {
      throw new Error(`Invalid limit: ${limit}. Must be an integer between 0 and 10000.`);
    }

    // 4. If no JXAExecutor, return empty result (backward compatibility)
    if (!this.jxaExecutor) {
      return this.mockExecuteGetElementsResult(resolvedApp, containerSpec, elementType, limit);
    }

    // 5. Build JXA to get elements
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

    // 6. Execute JXA
    const result = await this.jxaExecutor.execute(jxaCode);

    // 7. Parse result and handle errors
    const parsed = this.resultParser.parse(result, { appName: resolvedApp });

    if (!parsed.success) {
      throw new Error(this.formatJxaError(parsed.error!));
    }

    const jxaResult = parsed.data || { count: 0, items: [] };

    // 8. Create references for each element
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

    // 9. Return elements with metadata
    return {
      elements,
      count: jxaResult.count,
      hasMore: jxaResult.count > limit
    };
  }

  /**
   * Get elements from a container with their properties in a single batch operation.
   * Reduces round trips from 2N+1 to 1-2 by fetching elements AND properties together.
   *
   * @param container - Reference ID or ObjectSpecifier
   * @param elementType - Type of elements to retrieve (singular)
   * @param properties - Array of property names to fetch per element
   * @param app - Application name (required when container is ObjectSpecifier)
   * @param limit - Maximum number of elements to return (default: 100)
   * @returns Elements with embedded references and properties
   */
  async getElementsWithProperties(
    container: string | ObjectSpecifier,
    elementType: string,
    properties: string[],
    app?: string,
    limit: number = 100
  ): Promise<{
    elements: Array<{
      reference: ObjectReference;
      properties: Record<string, any>;
    }>;
    count: number;
    hasMore: boolean;
  }> {
    // 1. Resolve container (same logic as getElements)
    let containerSpec: ObjectSpecifier;
    let resolvedApp: string;

    if (typeof container === 'string') {
      const reference = this.referenceStore.get(container);
      if (!reference) {
        throw new Error(`Reference not found: ${container}. The referenced object may have been closed or deleted. Please re-query the object to get a fresh reference.`);
      }
      containerSpec = reference.specifier;
      resolvedApp = reference.app;
    } else {
      if (!app) {
        throw new Error('App parameter is required when container is an ObjectSpecifier');
      }
      containerSpec = container;
      resolvedApp = app;
    }

    // 2. Validate inputs
    this.sanitizeForJxa(elementType, 'elementType');
    if (!Number.isInteger(limit) || limit < 0 || limit > 10000) {
      throw new Error(`Invalid limit: ${limit}. Must be an integer between 0 and 10000.`);
    }
    if (!properties) {
      throw new Error('Properties parameter is required');
    }
    if (properties.length === 0) {
      throw new Error('Properties array must not be empty');
    }

    // Validate property names
    const sanitizedProps = properties.map(prop => {
      const sanitized = this.sanitizeForJxa(prop, 'property');
      return this.camelCase(sanitized);
    });

    // 3. If no JXAExecutor, return empty result
    if (!this.jxaExecutor) {
      return { elements: [], count: 0, hasMore: false };
    }

    // 4. Build single JXA script that fetches elements AND properties
    const containerPath = this.buildObjectPath(containerSpec, "app");
    const pluralElementType = this.pluralize(elementType);

    const propertyAccessors = sanitizedProps.map(prop => {
      const escaped = this.escapeJxaString(prop);
      return this.buildPropertyAccessorIIFE(escaped, 'el');
    }).join(',\n          ');

    const jxaCode = `(() => {
  const app = Application("${this.escapeJxaString(resolvedApp)}");
  const container = ${containerPath};
  const elements = container.${pluralElementType};
  const count = elements.length;
  const items = [];
  for (let i = 0; i < Math.min(count, ${limit}); i++) {
    const el = elements[i];
    items.push({
      index: i,
      props: {
          ${propertyAccessors}
      }
    });
  }
  return JSON.stringify({ count, items });
})()`;

    // 5. Execute JXA
    const result = await this.jxaExecutor.execute(jxaCode);

    // 6. Parse result
    const parsed = this.resultParser.parse(result, { appName: resolvedApp });
    if (!parsed.success) {
      throw new Error(this.formatJxaError(parsed.error!));
    }

    const jxaResult = parsed.data || { count: 0, items: [] };

    // 7. Create references and post-process properties for each element
    const elements = jxaResult.items.map((item: any, index: number) => {
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

      // Post-process properties: convert markers to references
      const processedProps: Record<string, any> = item.props || {};
      for (const key of Object.keys(processedProps)) {
        const val = processedProps[key];
        if (val && typeof val === 'object') {
          if (val._type === 'reference_list' &&
              typeof val.property === 'string' &&
              typeof val.count === 'number' && Number.isInteger(val.count) && val.count >= 0) {
            processedProps[key] = this.createPropertyListReferences(
              resolvedApp,
              elementSpec,
              val.property,
              val.count
            );
          } else if (val._type === 'object_reference' && typeof val.property === 'string') {
            processedProps[key] = this.createPropertyReference(
              resolvedApp,
              elementSpec,
              val.property
            );
          }
        }
      }

      return {
        reference,
        properties: processedProps
      };
    });

    return {
      elements,
      count: jxaResult.count,
      hasMore: jxaResult.count > limit
    };
  }

  /**
   * Build a JXA IIFE that accesses a property with:
   * - Array-of-objects detection (reference_list marker)
   * - Single-object detection (object_reference marker, with JSON.stringify check
   *   to distinguish real JXA specifiers from plain JS objects like {x:1, y:2})
   * - Per-property error resilience (try-catch returning _error marker)
   *
   * @param escapedProp - The escaped property name (already sanitized + escaped)
   * @param objVar - The variable name for the target object (e.g., 'obj' or 'el')
   * @returns JXA IIFE string for inclusion in a JSON object literal
   */
  private buildPropertyAccessorIIFE(escapedProp: string, objVar: string): string {
    return `${escapedProp}: (() => {
      try {
        const val = ${objVar}.${escapedProp}();
        if (Array.isArray(val) && val.length > 0 && val.every(item => typeof item === 'object' && item !== null)) {
          try {
            return { _type: 'reference_list', property: '${escapedProp}', count: val.length, items: val.map((_, i) => ({ index: i })) };
          } catch(e) {
            return val;
          }
        }
        if (!Array.isArray(val) && typeof val === 'object' && val !== null) {
          try {
            const str = JSON.stringify(val);
            if (str === undefined || str === 'null' || str === '{}') {
              return { _type: 'object_reference', property: '${escapedProp}' };
            }
            return val;
          } catch(e) {
            return { _type: 'object_reference', property: '${escapedProp}' };
          }
        }
        return val;
      } catch(e) {
        try { return String(${objVar}.${escapedProp}()); } catch(e2) {}
        return { _error: e.message || 'property access failed' };
      }
    })()`;
  }

  /**
   * Create references for items in a property-returned list.
   *
   * When a property like `selectedMessages` returns an array of JXA object specifiers,
   * this method creates individual references for each item. Each reference's specifier
   * is an ElementSpecifier with:
   * - element: inferred from property name (strip trailing 's' for plural, e.g., selectedMessages → message)
   * - index: position in the array
   * - container: a PropertySpecifier for the property on the parent object
   *
   * @param app - The application name
   * @param parentSpecifier - The specifier of the parent object that owns the property
   * @param propertyName - The camelCase property name (e.g., "selectedMessages")
   * @param count - Number of items in the list
   * @returns Array of reference IDs for each item
   */
  createPropertyListReferences(
    app: string,
    parentSpecifier: ObjectSpecifier,
    propertyName: string,
    count: number
  ): string[] {
    // Infer element type from property name:
    // "selectedMessages" → "message", "windows" → "window"
    const elementType = this.singularize(propertyName);

    // Build a PropertySpecifier for the property on the parent
    const propertySpec: PropertySpecifier = {
      type: 'property',
      property: propertyName,
      of: parentSpecifier
    };

    const referenceIds: string[] = [];
    for (let i = 0; i < count; i++) {
      const elementSpec: ElementSpecifier = {
        type: 'element',
        element: elementType,
        index: i,
        container: propertySpec
      };

      const refId = this.referenceStore.create(app, elementType, elementSpec);
      referenceIds.push(refId);
    }

    return referenceIds;
  }

  /**
   * Create a reference for a single object-type property.
   *
   * When a property like `mailbox` or `currentTab` returns a JXA object specifier,
   * this method creates a reference for it. The reference's specifier is a
   * PropertySpecifier for the property on the parent object.
   *
   * @param app - The application name
   * @param parentSpecifier - The specifier of the parent object that owns the property
   * @param propertyName - The camelCase property name (e.g., "mailbox", "currentTab")
   * @returns A single reference ID string
   */
  createPropertyReference(
    app: string,
    parentSpecifier: ObjectSpecifier,
    propertyName: string
  ): string {
    // Infer element type from property name
    const elementType = this.singularize(propertyName);

    // Build a PropertySpecifier for the property on the parent
    const propertySpec: PropertySpecifier = {
      type: 'property',
      property: propertyName,
      of: parentSpecifier
    };

    const refId = this.referenceStore.create(app, elementType, propertySpec);
    return refId;
  }

  /**
   * Infer singular element type from a property name.
   * Strips common prefixes (like "selected") and converts plural to singular.
   *
   * Examples:
   * - "selectedMessages" → "message"
   * - "windows" → "window"
   * - "selection" → "selection" (no change for non-plural)
   *
   * @param propertyName - The camelCase property name
   * @returns Inferred singular element type
   */
  private singularize(propertyName: string): string {
    // Strip common prefixes like "selected", "visible", "current"
    let name = propertyName;
    const prefixes = ['selected', 'visible', 'current', 'open', 'recent'];
    for (const prefix of prefixes) {
      if (name.startsWith(prefix) && name.length > prefix.length) {
        name = name.charAt(prefix.length).toLowerCase() + name.slice(prefix.length + 1);
        break;
      }
    }

    // Convert plural to singular
    if (name.endsWith('ies') && name.length > 3) {
      return name.slice(0, -3) + 'y';
    }
    if (name.endsWith('ses') || name.endsWith('xes') || name.endsWith('ches') || name.endsWith('shes')) {
      return name.slice(0, -2);
    }
    if (name.endsWith('s') && !name.endsWith('ss') && name.length > 1) {
      return name.slice(0, -1);
    }

    return name;
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

    // Character allowlist check — also blocks prototype pollution vectors
    // (e.g., __proto__, constructor) since underscores at start are only allowed
    // as part of the general [a-zA-Z0-9_ \-] pattern, not as prefix-only
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

      // When container is a PropertySpecifier (e.g., selectedMessages()), the result
      // is a plain JS array, not a JXA element collection. Index directly into it
      // instead of accessing a named element collection.
      // Correct:   app.messageViewers[0].selectedMessages()[0]
      // Incorrect: app.messageViewers[0].selectedMessages().messages[0]
      if (isPropertySpecifier(specifier.container)) {
        return `${containerPath}[${specifier.index}]`;
      }

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

    if (isApplicationSpecifier(specifier)) {
      // ApplicationSpecifier refers to the app object itself
      // JXA: just the app variable (e.g., "app" which is Application("Finder"))
      return appVar;
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
      throw new Error(`Reference not found: ${referenceId}. The referenced object may have been closed or deleted. Please re-query the object to get a fresh reference.`);
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
        !isPropertySpecifier(specifier) &&
        !isApplicationSpecifier(specifier)) {
      throw new Error(`Unsupported specifier type: ${(specifier as any).type}`);
    }

    // For PropertySpecifier with reference ID, validate reference exists
    if (isPropertySpecifier(specifier) && typeof specifier.of === "string") {
      const ref = this.referenceStore.get(specifier.of);
      if (!ref) {
        throw new Error(`Reference not found: ${specifier.of}. The referenced object may have been closed or deleted. Please re-query the object to get a fresh reference.`);
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
    if (isApplicationSpecifier(specifier)) return "application";
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
