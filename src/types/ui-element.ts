/**
 * UI Element Reference type for System Events UI automation.
 *
 * Stores the path from a process to a specific UI element,
 * enabling re-resolution across tool calls. Elements are ephemeral
 * (they disappear when the UI changes), so snapshotTime is included
 * for staleness warnings.
 */

/**
 * A single step in the path from process to UI element.
 */
export interface UIElementPathSegment {
  /** Accessibility role (e.g., "window", "button", "toolbar") */
  role: string;
  /** Index within parent's children of this role type */
  index: number;
  /** Optional display name for human readability */
  name?: string;
}

/**
 * Reference to a UI element discovered via ui_snapshot.
 * Stored in ReferenceStore with a specifier of this shape.
 */
export interface UIElementRef {
  type: "ui_element";
  appName: string;
  path: UIElementPathSegment[];
  snapshotTime: number;
}

/**
 * Staleness threshold for UI element references (30 seconds).
 * References older than this still work but include a warning.
 */
export const UI_ELEMENT_STALENESS_MS = 30_000;

/**
 * Type guard: Check if a value is a UIElementRef.
 */
export function isUIElementRef(value: unknown): value is UIElementRef {
  if (!value || typeof value !== "object") {
    return false;
  }

  const candidate = value as Record<string, unknown>;

  if (candidate.type !== "ui_element") {
    return false;
  }

  if (typeof candidate.appName !== "string" || candidate.appName.length === 0) {
    return false;
  }

  if (!Array.isArray(candidate.path)) {
    return false;
  }

  if (typeof candidate.snapshotTime !== "number") {
    return false;
  }

  // Validate each path segment
  for (const segment of candidate.path) {
    if (!isValidPathSegment(segment)) {
      return false;
    }
  }

  return true;
}

/**
 * Type guard: Check if a value is a valid UIElementPathSegment.
 */
function isValidPathSegment(value: unknown): value is UIElementPathSegment {
  if (!value || typeof value !== "object") {
    return false;
  }

  const candidate = value as Record<string, unknown>;

  if (typeof candidate.role !== "string" || candidate.role.length === 0) {
    return false;
  }

  if (typeof candidate.index !== "number" || !Number.isInteger(candidate.index) || candidate.index < 0) {
    return false;
  }

  if (candidate.name !== undefined && typeof candidate.name !== "string") {
    return false;
  }

  return true;
}
