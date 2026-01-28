/**
 * ReferenceStore - Manages stateful object references with TTL-based cleanup
 *
 * Stores references to macOS application objects and automatically cleans up
 * expired references based on a time-to-live (TTL) value.
 *
 * Phase 1: TTL-based cleanup (createdAt)
 * Phase 4: Will add LRU-based cleanup (lastAccessedAt)
 */

import { ObjectReference, ReferenceStats } from "../types/object-reference.js";
import { ObjectSpecifier } from "../types/object-specifier.js";

export class ReferenceStore {
  private references = new Map<string, ObjectReference>();
  private ttl: number; // Default 15 minutes (900,000ms)
  private cleanupInterval: NodeJS.Timeout | null = null;

  /**
   * Create a new ReferenceStore
   * @param ttl Time-to-live in milliseconds (default: 15 minutes)
   */
  constructor(ttl: number = 15 * 60 * 1000) {
    this.ttl = ttl;
    this.startCleanup();
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

    const reference: ObjectReference = {
      id,
      app,
      type,
      specifier,
      createdAt: now,
      lastAccessedAt: now,
    };

    this.references.set(id, reference);
    return id;
  }

  /**
   * Get reference by ID
   * @param id Reference ID
   * @returns ObjectReference or undefined if not found
   */
  get(id: string): ObjectReference | undefined {
    return this.references.get(id);
  }

  /**
   * Update lastAccessedAt timestamp
   * @param id Reference ID
   */
  touch(id: string): void {
    const ref = this.references.get(id);
    if (ref) {
      ref.lastAccessedAt = Date.now();
    }
  }

  /**
   * Remove expired references (TTL-based)
   *
   * Phase 1: Removes references where (now - createdAt) > TTL
   * Phase 4: Will use LRU-based on lastAccessedAt
   */
  cleanup(): void {
    const now = Date.now();
    const expired: string[] = [];

    for (const [id, ref] of this.references) {
      if (now - ref.createdAt > this.ttl) {
        expired.push(id);
      }
    }

    for (const id of expired) {
      this.references.delete(id);
    }
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
   * Start automatic cleanup timer (every 5 minutes)
   * @private
   */
  private startCleanup(): void {
    this.cleanupInterval = setInterval(() => {
      this.cleanup();
    }, 5 * 60 * 1000); // 5 minutes
  }

  /**
   * Stop automatic cleanup (for testing)
   */
  stopCleanup(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
  }

  /**
   * Clear all references (for testing)
   */
  clear(): void {
    this.references.clear();
  }

  /**
   * Generate unique reference ID
   * @private
   * @returns Reference ID with format "ref_<random>"
   */
  private generateId(): string {
    return `ref_${Math.random().toString(36).substring(2, 15)}`;
  }
}
