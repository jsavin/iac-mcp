/**
 * Integration Tests for Reference Lifecycle Management
 *
 * Tests reference management across the system:
 * - References are created with correct IDs (ref_ prefix)
 * - References persist across multiple tool calls
 * - References persist indefinitely (no TTL)
 * - LRU eviction removes least recently used references at capacity
 * - Touch and get() update lastAccessedAt
 * - Delete removes stale references
 * - Statistics tracking works correctly
 *
 * These tests verify that object references are properly managed
 * throughout their lifecycle in the system.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { ReferenceStore } from '../../src/execution/reference-store.js';
import { QueryExecutor } from '../../src/execution/query-executor.js';
import type { NamedSpecifier, ElementSpecifier } from '../../src/types/object-specifier.js';

describe('Reference Lifecycle Management', () => {
  let referenceStore: ReferenceStore;
  let queryExecutor: QueryExecutor;

  beforeEach(() => {
    referenceStore = new ReferenceStore();
    queryExecutor = new QueryExecutor(referenceStore);
  });

  afterEach(() => {
    referenceStore.clear();
  });

  describe('Reference Creation', () => {
    it('should create references with correct ID format', async () => {
      const spec: NamedSpecifier = {
        type: 'named',
        element: 'mailbox',
        name: 'inbox',
        container: 'application'
      };

      const ref = await queryExecutor.queryObject('Mail', spec);

      expect(ref.id).toMatch(/^ref_[a-f0-9-]+$/);
      expect(ref.id.startsWith('ref_')).toBe(true);
      expect(ref.id.length).toBeGreaterThan(4);
    });

    it('should create references with correct metadata', async () => {
      const spec: NamedSpecifier = {
        type: 'named',
        element: 'mailbox',
        name: 'inbox',
        container: 'application'
      };

      const ref = await queryExecutor.queryObject('Mail', spec);

      expect(ref.app).toBe('Mail');
      expect(ref.type).toBe('mailbox');
      expect(ref.specifier).toEqual(spec);
      expect(ref.createdAt).toBeDefined();
      expect(ref.lastAccessedAt).toBeDefined();
      expect(typeof ref.createdAt).toBe('number');
      expect(typeof ref.lastAccessedAt).toBe('number');
    });

    it('should create unique IDs for each reference', async () => {
      const spec1: NamedSpecifier = {
        type: 'named',
        element: 'mailbox',
        name: 'inbox',
        container: 'application'
      };

      const spec2: NamedSpecifier = {
        type: 'named',
        element: 'mailbox',
        name: 'drafts',
        container: 'application'
      };

      const ref1 = await queryExecutor.queryObject('Mail', spec1);
      const ref2 = await queryExecutor.queryObject('Mail', spec2);

      expect(ref1.id).not.toBe(ref2.id);
    });

    it('should initialize createdAt and lastAccessedAt to same time', async () => {
      const spec: NamedSpecifier = {
        type: 'named',
        element: 'mailbox',
        name: 'inbox',
        container: 'application'
      };

      const ref = await queryExecutor.queryObject('Mail', spec);

      expect(ref.createdAt).toBe(ref.lastAccessedAt);
    });
  });

  describe('Reference Persistence', () => {
    it('should persist references across multiple queries', async () => {
      const spec: NamedSpecifier = {
        type: 'named',
        element: 'mailbox',
        name: 'inbox',
        container: 'application'
      };

      const ref1 = await queryExecutor.queryObject('Mail', spec);
      const retrievedRef = referenceStore.get(ref1.id);

      expect(retrievedRef).toBeDefined();
      expect(retrievedRef?.id).toBe(ref1.id);
      expect(retrievedRef?.app).toBe('Mail');
      expect(retrievedRef?.type).toBe('mailbox');
    });

    it('should allow multiple references to exist simultaneously', async () => {
      const mailboxSpec: NamedSpecifier = {
        type: 'named',
        element: 'mailbox',
        name: 'inbox',
        container: 'application'
      };

      const windowSpec: ElementSpecifier = {
        type: 'element',
        element: 'window',
        index: 0,
        container: 'application'
      };

      const mailboxRef = await queryExecutor.queryObject('Mail', mailboxSpec);
      const windowRef = await queryExecutor.queryObject('Finder', windowSpec);

      expect(referenceStore.get(mailboxRef.id)).toBeDefined();
      expect(referenceStore.get(windowRef.id)).toBeDefined();
    });

    it('should maintain reference data integrity across retrievals', async () => {
      const spec: NamedSpecifier = {
        type: 'named',
        element: 'mailbox',
        name: 'inbox',
        container: 'application'
      };

      const ref = await queryExecutor.queryObject('Mail', spec);

      // Retrieve multiple times — data should be consistent
      const retrieved1 = referenceStore.get(ref.id);
      const retrieved2 = referenceStore.get(ref.id);

      // Note: lastAccessedAt will differ due to auto-touch on get()
      expect(retrieved1?.app).toBe(retrieved2?.app);
      expect(retrieved1?.type).toBe(retrieved2?.type);
      expect(retrieved1?.specifier).toEqual(retrieved2?.specifier);
    });
  });

  describe('No TTL - References persist indefinitely', () => {
    it('should not expire references after 15 minutes', () => {
      vi.useFakeTimers();
      const now = Date.now();
      vi.setSystemTime(now);

      const referenceId = referenceStore.create('Mail', 'mailbox', {
        type: 'named',
        element: 'mailbox',
        name: 'inbox',
        container: 'application'
      });

      // Reference should exist
      expect(referenceStore.get(referenceId)).toBeDefined();

      // Advance time past old TTL (15 minutes + 1 second)
      vi.advanceTimersByTime((15 * 60 * 1000) + 1000);

      // Reference should STILL exist (no TTL)
      expect(referenceStore.get(referenceId)).toBeDefined();

      vi.useRealTimers();
    });

    it('should not expire references after 24 hours', () => {
      vi.useFakeTimers();
      const now = Date.now();
      vi.setSystemTime(now);

      const referenceId = referenceStore.create('Mail', 'mailbox', {
        type: 'named',
        element: 'mailbox',
        name: 'inbox',
        container: 'application'
      });

      // Advance time 24 hours
      vi.advanceTimersByTime(24 * 60 * 60 * 1000);

      // Reference should STILL exist (no TTL)
      expect(referenceStore.get(referenceId)).toBeDefined();

      vi.useRealTimers();
    });

    it('should keep all references regardless of age when below capacity', () => {
      vi.useFakeTimers();
      const now = Date.now();
      vi.setSystemTime(now);

      const ref1 = referenceStore.create('Mail', 'mailbox', {
        type: 'named',
        element: 'mailbox',
        name: 'inbox',
        container: 'application'
      });

      // Advance time 10 minutes
      vi.advanceTimersByTime(10 * 60 * 1000);

      const ref2 = referenceStore.create('Mail', 'mailbox', {
        type: 'named',
        element: 'mailbox',
        name: 'drafts',
        container: 'application'
      });

      // Advance time another 10 minutes (ref1 at 20 min, ref2 at 10 min)
      vi.advanceTimersByTime(10 * 60 * 1000);

      // Both should still exist — no TTL
      expect(referenceStore.get(ref1)).toBeDefined();
      expect(referenceStore.get(ref2)).toBeDefined();

      vi.useRealTimers();
    });
  });

  describe('Reference Touch (lastAccessedAt)', () => {
    it('should update lastAccessedAt when touched', () => {
      vi.useFakeTimers();
      const now = Date.now();
      vi.setSystemTime(now);

      const spec: NamedSpecifier = {
        type: 'named',
        element: 'mailbox',
        name: 'inbox',
        container: 'application'
      };

      const referenceId = referenceStore.create('Mail', 'mailbox', spec);
      const ref = referenceStore.get(referenceId)!;
      const originalLastAccessed = ref.lastAccessedAt;

      // Advance time 5 minutes
      vi.advanceTimersByTime(5 * 60 * 1000);

      // Touch the reference
      referenceStore.touch(referenceId);

      const touchedRef = referenceStore.get(referenceId)!;
      expect(touchedRef.lastAccessedAt).toBeGreaterThan(originalLastAccessed);
      expect(touchedRef.lastAccessedAt).toBe(now + (5 * 60 * 1000));

      vi.useRealTimers();
    });

    it('should update lastAccessedAt on get()', () => {
      vi.useFakeTimers();
      const now = Date.now();
      vi.setSystemTime(now);

      const referenceId = referenceStore.create('Mail', 'mailbox', {
        type: 'named',
        element: 'mailbox',
        name: 'inbox',
        container: 'application'
      });

      // Advance time 5 minutes
      vi.advanceTimersByTime(5 * 60 * 1000);

      // get() should auto-touch
      const ref = referenceStore.get(referenceId)!;
      expect(ref.lastAccessedAt).toBe(now + (5 * 60 * 1000));

      vi.useRealTimers();
    });

    it('should update lastAccessedAt on getProperties', async () => {
      vi.useFakeTimers();
      const now = Date.now();
      vi.setSystemTime(now);

      const spec: NamedSpecifier = {
        type: 'named',
        element: 'mailbox',
        name: 'inbox',
        container: 'application'
      };

      const ref = await queryExecutor.queryObject('Mail', spec);
      const originalLastAccessed = ref.lastAccessedAt;

      // Advance time 2 minutes
      vi.advanceTimersByTime(2 * 60 * 1000);

      // Call getProperties
      await queryExecutor.getProperties(ref.id, ['name']);

      const updatedRef = referenceStore.get(ref.id)!;
      expect(updatedRef.lastAccessedAt).toBeGreaterThan(originalLastAccessed);

      vi.useRealTimers();
    });
  });

  describe('Delete', () => {
    it('should remove a specific reference', () => {
      const refId = referenceStore.create('Mail', 'mailbox', {
        type: 'named',
        element: 'mailbox',
        name: 'inbox',
        container: 'application'
      });

      expect(referenceStore.get(refId)).toBeDefined();

      const result = referenceStore.delete(refId);
      expect(result).toBe(true);
      expect(referenceStore.get(refId)).toBeUndefined();
    });

    it('should return false for non-existent reference', () => {
      const result = referenceStore.delete('ref_nonexistent');
      expect(result).toBe(false);
    });

    it('should not affect other references when deleting one', () => {
      const ref1 = referenceStore.create('Mail', 'mailbox', {
        type: 'named',
        element: 'mailbox',
        name: 'inbox',
        container: 'application'
      });

      const ref2 = referenceStore.create('Finder', 'window', {
        type: 'element',
        element: 'window',
        index: 0,
        container: 'application'
      });

      referenceStore.delete(ref1);

      expect(referenceStore.get(ref1)).toBeUndefined();
      expect(referenceStore.get(ref2)).toBeDefined();
    });
  });

  describe('LRU Eviction', () => {
    it('should evict least recently used when over capacity', () => {
      vi.useFakeTimers();
      const now = Date.now();
      vi.setSystemTime(now);

      const smallStore = new ReferenceStore(3);

      const ref1 = smallStore.create('Mail', 'mailbox', {
        type: 'named', element: 'mailbox', name: 'inbox', container: 'application'
      });
      vi.advanceTimersByTime(10);
      const ref2 = smallStore.create('Mail', 'mailbox', {
        type: 'named', element: 'mailbox', name: 'drafts', container: 'application'
      });
      vi.advanceTimersByTime(10);
      const ref3 = smallStore.create('Finder', 'window', {
        type: 'element', element: 'window', index: 0, container: 'application'
      });

      expect(smallStore.getStats().totalReferences).toBe(3);

      // Touch ref1 to make it the most recently accessed
      vi.advanceTimersByTime(10);
      smallStore.touch(ref1);

      // Add a 4th — should evict ref2 (least recently accessed)
      vi.advanceTimersByTime(10);
      const ref4 = smallStore.create('Finder', 'window', {
        type: 'element', element: 'window', index: 1, container: 'application'
      });

      expect(smallStore.getStats().totalReferences).toBe(3);
      expect(smallStore.get(ref1)).toBeDefined();  // recently touched
      expect(smallStore.get(ref4)).toBeDefined();  // just created
      // ref2 was evicted (oldest lastAccessedAt)

      vi.useRealTimers();
    });

    it('should never evict a just-created reference even with same timestamps', () => {
      vi.useFakeTimers();
      vi.setSystemTime(1000);

      const smallStore = new ReferenceStore(2);

      // All 3 created at exact same timestamp
      const ref1 = smallStore.create('Mail', 'mailbox', {
        type: 'named', element: 'mailbox', name: 'inbox', container: 'application'
      });
      const ref2 = smallStore.create('Mail', 'mailbox', {
        type: 'named', element: 'mailbox', name: 'drafts', container: 'application'
      });
      const ref3 = smallStore.create('Mail', 'mailbox', {
        type: 'named', element: 'mailbox', name: 'sent', container: 'application'
      });

      // Store should be at capacity
      expect(smallStore.getStats().totalReferences).toBe(2);

      // The most recently created ref must always survive
      expect(smallStore.get(ref3)).toBeDefined();

      // ref1 should have been evicted (inserted first, so oldest in Map order)
      // ref2 or ref3 survive — but ref3 is guaranteed since eviction
      // happens before its insertion

      vi.useRealTimers();
    });

    it('should not evict when below capacity', () => {
      const smallStore = new ReferenceStore(5);

      for (let i = 0; i < 5; i++) {
        smallStore.create('Mail', 'mailbox', {
          type: 'named', element: 'mailbox', name: `box-${i}`, container: 'application'
        });
      }

      expect(smallStore.getStats().totalReferences).toBe(5);
    });
  });

  describe('Statistics Tracking', () => {
    it('should track total references created', async () => {
      const initialStats = referenceStore.getStats();

      const spec1: NamedSpecifier = {
        type: 'named',
        element: 'mailbox',
        name: 'inbox',
        container: 'application'
      };

      const spec2: NamedSpecifier = {
        type: 'named',
        element: 'mailbox',
        name: 'drafts',
        container: 'application'
      };

      await queryExecutor.queryObject('Mail', spec1);
      await queryExecutor.queryObject('Mail', spec2);

      const stats = referenceStore.getStats();
      expect(stats.totalReferences).toBe(initialStats.totalReferences + 2);
    });

    it('should track active references count', async () => {
      const spec: NamedSpecifier = {
        type: 'named',
        element: 'mailbox',
        name: 'inbox',
        container: 'application'
      };

      await queryExecutor.queryObject('Mail', spec);

      const stats = referenceStore.getStats();
      expect(stats.totalReferences).toBeGreaterThan(0);
    });

    it('should update count after delete', () => {
      const ref1 = referenceStore.create('Mail', 'mailbox', {
        type: 'named',
        element: 'mailbox',
        name: 'inbox',
        container: 'application'
      });

      referenceStore.create('Mail', 'mailbox', {
        type: 'named',
        element: 'mailbox',
        name: 'drafts',
        container: 'application'
      });

      expect(referenceStore.getStats().totalReferences).toBe(2);

      referenceStore.delete(ref1);
      expect(referenceStore.getStats().totalReferences).toBe(1);
    });
  });

  describe('Property returning reference list → use returned references', () => {
    it('should create usable references from property-returned object lists', async () => {
      // Simulate: query message viewer → get selectedMessages → use returned refs
      const viewerSpec: NamedSpecifier = {
        type: 'named',
        element: 'message viewer',
        name: 'main',
        container: 'application'
      };

      // Step 1: Query the message viewer
      const viewerRef = await queryExecutor.queryObject('Mail', viewerSpec);
      expect(viewerRef.id).toMatch(/^ref_/);

      // Step 2: Use createPropertyListReferences (simulating what getProperties
      // does after receiving reference_list from JXA)
      const refIds = (queryExecutor as any).createPropertyListReferences(
        'Mail',
        viewerRef.specifier,
        'selectedMessages',
        2
      );

      expect(refIds.length).toBe(2);

      // Step 3: Each returned reference should be retrievable and usable
      for (let i = 0; i < refIds.length; i++) {
        const msgRef = referenceStore.get(refIds[i]);
        expect(msgRef).toBeDefined();
        expect(msgRef!.app).toBe('Mail');
        expect(msgRef!.type).toBe('message');

        // Verify specifier chain is correct for JXA path generation
        const spec = msgRef!.specifier as ElementSpecifier;
        expect(spec.type).toBe('element');
        expect(spec.index).toBe(i);

        // Container should be PropertySpecifier pointing back to viewer
        const container = spec.container;
        expect(typeof container).toBe('object');
        expect((container as any).type).toBe('property');
        expect((container as any).property).toBe('selectedMessages');
      }
    });

    it('should maintain reference lifecycle for property-list-created references', async () => {
      const viewerSpec: ElementSpecifier = {
        type: 'element',
        element: 'message viewer',
        index: 0,
        container: 'application'
      };

      const viewerRef = await queryExecutor.queryObject('Mail', viewerSpec);

      const refIds = (queryExecutor as any).createPropertyListReferences(
        'Mail',
        viewerRef.specifier,
        'selectedMessages',
        2
      );

      // References should be in the store
      const totalCount = referenceStore.getStats().totalReferences;
      expect(totalCount).toBeGreaterThanOrEqual(3); // viewer + 2 messages

      // References should be deletable
      referenceStore.delete(refIds[0]);
      expect(referenceStore.get(refIds[0])).toBeUndefined();
      expect(referenceStore.get(refIds[1])).toBeDefined();
    });
  });

  describe('Backward Compatibility', () => {
    it('should be safe to call stopCleanup multiple times', () => {
      referenceStore.stopCleanup();
      referenceStore.stopCleanup();
      referenceStore.stopCleanup();

      // Should not throw
      expect(true).toBe(true);
    });

    it('should handle clear with no references', () => {
      referenceStore.clear();

      const stats = referenceStore.getStats();
      expect(stats.totalReferences).toBe(0);
    });
  });

  describe('Reference Retrieval', () => {
    it('should return undefined for non-existent reference', () => {
      const ref = referenceStore.get('ref_nonexistent');
      expect(ref).toBeUndefined();
    });

    it('should return undefined for invalid reference ID format', () => {
      const ref = referenceStore.get('invalid_id');
      expect(ref).toBeUndefined();
    });

    it('should retrieve references by exact ID match', async () => {
      const spec: NamedSpecifier = {
        type: 'named',
        element: 'mailbox',
        name: 'inbox',
        container: 'application'
      };

      const ref = await queryExecutor.queryObject('Mail', spec);
      const retrieved = referenceStore.get(ref.id);

      expect(retrieved).toBeDefined();
      expect(retrieved?.id).toBe(ref.id);
    });
  });
});
