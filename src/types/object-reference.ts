/**
 * Object Reference Types for Stateful Query System
 *
 * Defines types for storing and managing persistent references
 * to macOS application objects across multiple queries.
 */

import type { ObjectSpecifier } from "./object-specifier.js";

/**
 * A persistent reference to a macOS application object
 *
 * Allows LLMs to reference the same object across multiple queries
 * without re-specifying the full object path each time.
 *
 * Example:
 *   Query 1: Get first window → Returns ref_abc123
 *   Query 2: Get name of ref_abc123 → Uses stored specifier
 */
export interface ObjectReference {
  /**
   * Unique identifier for this reference (format: "ref_" + random string)
   */
  id: string;

  /**
   * Bundle ID of the application this object belongs to
   * (e.g., "com.apple.finder")
   */
  app: string;

  /**
   * Object class from the application's SDEF
   * (e.g., "window", "document", "folder")
   */
  type: string;

  /**
   * Specifier chain describing how to resolve this object
   * (e.g., {type: "element", element: "window", index: 0, container: "application"})
   */
  specifier: ObjectSpecifier;

  /**
   * Unix timestamp (ms) when this reference was created
   */
  createdAt: number;

  /**
   * Unix timestamp (ms) when this reference was last accessed
   * Used for LRU cache eviction in Phase 4
   */
  lastAccessedAt: number;

  /**
   * Optional application-specific metadata
   * (e.g., cached properties, display name for debugging)
   */
  metadata?: Record<string, any>;
}

/**
 * Statistics about the reference store
 *
 * Used for monitoring and debugging the reference system
 */
export interface ReferenceStats {
  /**
   * Total number of references currently stored
   */
  totalReferences: number;

  /**
   * Count of references per application bundle ID
   */
  referencesPerApp: Record<string, number>;

  /**
   * Timestamp of the oldest reference in the store
   */
  oldestReference: number;

  /**
   * Timestamp of the newest reference in the store
   */
  newestReference: number;
}
