/**
 * Object Specifier Types for Stateful Query System
 *
 * Defines the type system for referencing macOS application objects
 * across multiple queries. Based on AppleScript/JXA object model.
 */

/**
 * Specifies an element by index (e.g., "window 1", "document 2")
 */
export interface ElementSpecifier {
  type: "element";
  element: string; // Element class name (e.g., "window", "document")
  index: number; // Zero-based index
  container: SpecifierContainer;
}

/**
 * Specifies an element by name (e.g., "window 'Main'", "document 'README'")
 */
export interface NamedSpecifier {
  type: "named";
  element: string; // Element class name
  name: string; // Element name
  container: SpecifierContainer;
}

/**
 * Specifies an element by ID (e.g., "window id 12345")
 */
export interface IdSpecifier {
  type: "id";
  element: string; // Element class name
  id: string; // Element ID (app-specific)
  container: SpecifierContainer;
}

/**
 * Specifies a property of an object (e.g., "name of window 1")
 */
export interface PropertySpecifier {
  type: "property";
  property: string; // Property name
  of: ObjectSpecifier | string; // Parent specifier or reference ID
}

/**
 * Specifies the application object itself (e.g., to set frontmost or activate)
 */
export interface ApplicationSpecifier {
  type: "application";
  // No additional fields - this refers to the app passed in the query
}

/**
 * Union of all specifier types
 */
export type ObjectSpecifier =
  | ElementSpecifier
  | NamedSpecifier
  | IdSpecifier
  | PropertySpecifier
  | ApplicationSpecifier;

/**
 * Container can be another specifier or the application itself
 */
export type SpecifierContainer = ObjectSpecifier | "application";

/**
 * Type guard: Check if value is an ElementSpecifier
 */
export function isElementSpecifier(
  spec: unknown
): spec is ElementSpecifier {
  if (!spec || typeof spec !== "object") {
    return false;
  }

  const candidate = spec as Record<string, unknown>;

  return (
    candidate.type === "element" &&
    typeof candidate.element === "string" &&
    typeof candidate.index === "number" &&
    candidate.container !== undefined
  );
}

/**
 * Type guard: Check if value is a NamedSpecifier
 */
export function isNamedSpecifier(
  spec: unknown
): spec is NamedSpecifier {
  if (!spec || typeof spec !== "object") {
    return false;
  }

  const candidate = spec as Record<string, unknown>;

  return (
    candidate.type === "named" &&
    typeof candidate.element === "string" &&
    typeof candidate.name === "string" &&
    candidate.container !== undefined
  );
}

/**
 * Type guard: Check if value is an IdSpecifier
 */
export function isIdSpecifier(spec: unknown): spec is IdSpecifier {
  if (!spec || typeof spec !== "object") {
    return false;
  }

  const candidate = spec as Record<string, unknown>;

  return (
    candidate.type === "id" &&
    typeof candidate.element === "string" &&
    typeof candidate.id === "string" &&
    candidate.container !== undefined
  );
}

/**
 * Type guard: Check if value is a PropertySpecifier
 */
export function isPropertySpecifier(
  spec: unknown
): spec is PropertySpecifier {
  if (!spec || typeof spec !== "object") {
    return false;
  }

  const candidate = spec as Record<string, unknown>;

  return (
    candidate.type === "property" &&
    typeof candidate.property === "string" &&
    candidate.of !== undefined
  );
}

/**
 * Type guard: Check if value is an ApplicationSpecifier
 */
export function isApplicationSpecifier(
  spec: unknown
): spec is ApplicationSpecifier {
  if (!spec || typeof spec !== "object") {
    return false;
  }

  const candidate = spec as Record<string, unknown>;

  return candidate.type === "application";
}

/**
 * Check if a string is a reference ID (starts with "ref_")
 */
export function isReferenceId(value: unknown): boolean {
  return typeof value === "string" && value.startsWith("ref_");
}

/**
 * Validates that a container is either "application" or a valid specifier.
 */
function isValidContainer(container: unknown): boolean {
  if (container === "application") {
    return true;
  }
  // Recursively validate nested specifier
  return isValidObjectSpecifier(container);
}

/**
 * Type guard: Check if value is a valid ObjectSpecifier
 * Performs comprehensive runtime validation including recursive validation of nested specifiers.
 */
export function isValidObjectSpecifier(spec: unknown): spec is ObjectSpecifier {
  if (!spec || typeof spec !== "object") {
    return false;
  }

  // Check for ElementSpecifier
  if (isElementSpecifier(spec)) {
    return isValidContainer(spec.container);
  }

  // Check for NamedSpecifier
  if (isNamedSpecifier(spec)) {
    return isValidContainer(spec.container);
  }

  // Check for IdSpecifier
  if (isIdSpecifier(spec)) {
    return isValidContainer(spec.container);
  }

  // Check for PropertySpecifier
  if (isPropertySpecifier(spec)) {
    // "of" can be a reference ID (string starting with "ref_") or another specifier
    if (typeof spec.of === "string") {
      return isReferenceId(spec.of);
    }
    return isValidObjectSpecifier(spec.of);
  }

  // Check for ApplicationSpecifier
  if (isApplicationSpecifier(spec)) {
    return true;
  }

  return false;
}

/**
 * Result of specifier validation with detailed error information.
 */
export interface SpecifierValidationResult {
  valid: boolean;
  errors: string[];
}

/**
 * Validates an ObjectSpecifier and returns detailed error information.
 * Use this for runtime validation in MCP handlers.
 */
export function validateObjectSpecifier(spec: unknown): SpecifierValidationResult {
  const errors: string[] = [];

  if (!spec) {
    return { valid: false, errors: ['Specifier is null or undefined'] };
  }

  if (typeof spec !== "object") {
    return { valid: false, errors: [`Specifier must be an object, got ${typeof spec}`] };
  }

  const candidate = spec as Record<string, unknown>;

  // Check for required 'type' field
  if (!candidate.type || typeof candidate.type !== "string") {
    errors.push('Missing or invalid "type" field');
    return { valid: false, errors };
  }

  // Validate based on type
  switch (candidate.type) {
    case "element":
      if (typeof candidate.element !== "string") {
        errors.push('ElementSpecifier: "element" must be a string');
      }
      if (typeof candidate.index !== "number") {
        errors.push('ElementSpecifier: "index" must be a number');
      }
      if (candidate.container === undefined) {
        errors.push('ElementSpecifier: "container" is required');
      } else if (candidate.container !== "application" && !isValidObjectSpecifier(candidate.container)) {
        errors.push('ElementSpecifier: "container" must be "application" or a valid specifier');
      }
      break;

    case "named":
      if (typeof candidate.element !== "string") {
        errors.push('NamedSpecifier: "element" must be a string');
      }
      if (typeof candidate.name !== "string") {
        errors.push('NamedSpecifier: "name" must be a string');
      }
      if (candidate.container === undefined) {
        errors.push('NamedSpecifier: "container" is required');
      } else if (candidate.container !== "application" && !isValidObjectSpecifier(candidate.container)) {
        errors.push('NamedSpecifier: "container" must be "application" or a valid specifier');
      }
      break;

    case "id":
      if (typeof candidate.element !== "string") {
        errors.push('IdSpecifier: "element" must be a string');
      }
      if (typeof candidate.id !== "string") {
        errors.push('IdSpecifier: "id" must be a string');
      }
      if (candidate.container === undefined) {
        errors.push('IdSpecifier: "container" is required');
      } else if (candidate.container !== "application" && !isValidObjectSpecifier(candidate.container)) {
        errors.push('IdSpecifier: "container" must be "application" or a valid specifier');
      }
      break;

    case "property":
      if (typeof candidate.property !== "string") {
        errors.push('PropertySpecifier: "property" must be a string');
      }
      if (candidate.of === undefined) {
        errors.push('PropertySpecifier: "of" is required');
      } else if (typeof candidate.of === "string") {
        if (!isReferenceId(candidate.of)) {
          errors.push('PropertySpecifier: "of" string must be a valid reference ID (starts with "ref_")');
        }
      } else if (!isValidObjectSpecifier(candidate.of)) {
        errors.push('PropertySpecifier: "of" must be a valid specifier or reference ID');
      }
      break;

    case "application":
      // ApplicationSpecifier has no additional fields to validate
      break;

    default:
      errors.push(`Unknown specifier type: "${candidate.type}". Must be one of: element, named, id, property, application`);
  }

  return { valid: errors.length === 0, errors };
}
