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
 * Union of all specifier types
 */
export type ObjectSpecifier =
  | ElementSpecifier
  | NamedSpecifier
  | IdSpecifier
  | PropertySpecifier;

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
 * Check if a string is a reference ID (starts with "ref_")
 */
export function isReferenceId(value: unknown): boolean {
  return typeof value === "string" && value.startsWith("ref_");
}
