/**
 * ReferenceStore - Manages stateful object references with TTL-based cleanup
 *
 * Stores references to macOS application objects and automatically cleans up
 * expired references based on a time-to-live (TTL) value.
 *
 * Phase 1: TTL-based cleanup (createdAt)
 * Phase 4: Will add LRU-based cleanup (lastAccessedAt)
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
    logRef("created", { id, app, type, specifier: specifier.type });
    return id;
  }

  /**
   * Get reference by ID
   * @param id Reference ID
   * @returns ObjectReference or undefined if not found
   */
  get(id: string): ObjectReference | undefined {
    const ref = this.references.get(id);
    if (!ref) {
      logRef("not_found", { id });
    }
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
        const exceededBy = now - ref.createdAt - this.ttl;
        logRef("expired", { id, exceededByMs: exceededBy });
      }
    }

    for (const id of expired) {
      this.references.delete(id);
    }

    if (expired.length > 0 || DEBUG_REFS) {
      logRef("cleanup_complete", {
        removed: expired.length,
        remaining: this.references.size
      });
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
