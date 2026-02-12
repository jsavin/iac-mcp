/**
 * ReferenceStore - Manages stateful object references with LRU eviction
 *
 * Stores references to macOS application objects. References are specifier
 * chains (data describing how to resolve an object), not live handles —
 * there's no app-side resource to clean up. A reference is valid as long
 * as the underlying object exists in the application.
 *
 * Eviction: LRU-based when store exceeds maxReferences cap. No TTL —
 * references live until evicted or the store is cleared.
 *
 * Debug logging: Set IAC_MCP_DEBUG_REFS=true to enable lifecycle logging
 */

import { randomUUID } from "node:crypto";
import { ObjectReference, ReferenceStats } from "../types/object-reference.js";
import { ObjectSpecifier } from "../types/object-specifier.js";

/**
 * Debug logging for reference lifecycle events.
 * Enabled via IAC_MCP_DEBUG_REFS=true environment variable.
 * Logs to stderr to avoid MCP protocol interference.
 */
const DEBUG_REFS = process.env.IAC_MCP_DEBUG_REFS === "true";

function logRef(event: string, data?: Record<string, unknown>): void {
  if (DEBUG_REFS) {
    const timestamp = new Date().toISOString();
    const dataStr = data ? ` ${JSON.stringify(data)}` : "";
    console.error(`[RefStore][${timestamp}] ${event}${dataStr}`);
  }
}

/** Default maximum number of references before LRU eviction kicks in */
const DEFAULT_MAX_REFERENCES = 1000;

export class ReferenceStore {
  private references = new Map<string, ObjectReference>();
  private maxReferences: number;

  /**
   * Create a new ReferenceStore
   * @param maxReferences Maximum references before LRU eviction (default: 1000)
   */
  constructor(maxReferences: number = DEFAULT_MAX_REFERENCES) {
    this.maxReferences = maxReferences;
  }

  /**
   * Create a new reference
   * @param app Bundle ID of the application (e.g., "com.apple.finder")
   * @param type Object class from SDEF (e.g., "window", "document")
   * @param specifier Specifier chain describing how to resolve the object
   * @returns Unique reference ID (format: "ref_<random>")
   */
  create(app: string, type: string, specifier: ObjectSpecifier): string {
    const id = this.generateId();
    const now = Date.now();

    // Evict BEFORE inserting to ensure the new reference is never
    // a candidate for immediate eviction (same-millisecond race)
    this.evictIfNeeded();

    const reference: ObjectReference = {
      id,
      app,
      type,
      specifier,
      createdAt: now,
      lastAccessedAt: now,
    };

    this.references.set(id, reference);
    logRef("created", { id, app, type, specifier: specifier.type });

    return id;
  }

  /**
   * Get reference by ID, automatically updating lastAccessedAt.
   * @sideEffect Mutates the reference's lastAccessedAt to Date.now()
   * @param id Reference ID
   * @returns ObjectReference or undefined if not found
   */
  get(id: string): ObjectReference | undefined {
    const ref = this.references.get(id);
    if (!ref) {
      logRef("not_found", { id });
      return undefined;
    }
    // Auto-touch on access
    ref.lastAccessedAt = Date.now();
    logRef("accessed", { id, ageMs: Date.now() - ref.createdAt });
    return ref;
  }

  /**
   * Update lastAccessedAt timestamp
   * @param id Reference ID
   */
  touch(id: string): void {
    const ref = this.references.get(id);
    if (ref) {
      const age = Date.now() - ref.createdAt;
      ref.lastAccessedAt = Date.now();
      logRef("touched", { id, ageMs: age });
    }
  }

  /**
   * Remove a specific reference by ID.
   * Used when a reference is known to be stale (object no longer exists).
   * @param id Reference ID to remove
   * @returns true if the reference was found and removed, false otherwise
   */
  delete(id: string): boolean {
    const existed = this.references.delete(id);
    if (existed) {
      logRef("deleted", { id });
    }
    return existed;
  }

  /**
   * Evict least recently used references when store exceeds capacity.
   * Removes the oldest (by lastAccessedAt) references to bring
   * the store back to maxReferences.
   *
   * Performance: O(n log n) due to sort. Acceptable at the default 1000-ref
   * cap. If maxReferences grows significantly (>10k), consider replacing
   * with a min-heap or doubly-linked list for O(1) eviction.
   */
  evictIfNeeded(): void {
    if (this.references.size < this.maxReferences) {
      return;
    }

    // Evict enough to make room for one new entry
    const toEvict = this.references.size - this.maxReferences + 1;  // +1 to free a slot

    // Sort by lastAccessedAt ascending (least recently used first)
    const sorted = [...this.references.entries()]
      .sort((a, b) => a[1].lastAccessedAt - b[1].lastAccessedAt);

    for (let i = 0; i < toEvict; i++) {
      const [id] = sorted[i];
      this.references.delete(id);
      logRef("evicted", { id, reason: "lru" });
    }

    logRef("eviction_complete", {
      evicted: toEvict,
      remaining: this.references.size
    });
  }

  /**
   * Get statistics about current references
   * @returns ReferenceStats object with counts and timestamps
   */
  getStats(): ReferenceStats {
    const referencesPerApp: Record<string, number> = {};
    let oldest = Date.now();
    let newest = 0;

    for (const ref of this.references.values()) {
      referencesPerApp[ref.app] = (referencesPerApp[ref.app] || 0) + 1;
      oldest = Math.min(oldest, ref.createdAt);
      newest = Math.max(newest, ref.createdAt);
    }

    return {
      totalReferences: this.references.size,
      referencesPerApp,
      oldestReference: oldest,
      newestReference: newest,
    };
  }

  /**
   * Stop automatic cleanup (kept for backward compatibility with tests)
   */
  stopCleanup(): void {
    // No-op: TTL-based cleanup has been removed.
    // Kept for backward compatibility with existing test teardown.
  }

  /**
   * Clear all references (for testing)
   */
  clear(): void {
    this.references.clear();
  }

  /**
   * Generate unique reference ID using cryptographically secure random UUID.
   * Uses crypto.randomUUID() to prevent collisions.
   *
   * @private
   * @returns Reference ID with format "ref_<uuid>"
   */
  private generateId(): string {
    return `ref_${randomUUID()}`;
  }
}
