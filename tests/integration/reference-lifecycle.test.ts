/**
 * Integration Tests for Reference Lifecycle Management
 *
 * Tests reference management across the system:
 * - References are created with correct IDs (ref_ prefix)
 * - References persist across multiple tool calls
 * - References expire after TTL (15 minutes)
 * - Cleanup removes expired references
 * - Touch updates lastAccessedAt
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
    referenceStore.cleanup();
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

      expect(ref.id).toMatch(/^ref_[a-z0-9]+$/);
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

      // Retrieve multiple times
      const retrieved1 = referenceStore.get(ref.id);
      const retrieved2 = referenceStore.get(ref.id);

      expect(retrieved1).toEqual(retrieved2);
      expect(retrieved1?.app).toBe('Mail');
      expect(retrieved1?.type).toBe('mailbox');
      expect(retrieved1?.specifier).toEqual(spec);
    });
  });

  describe('Reference Expiration', () => {
    it('should expire references after TTL', () => {
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

      // Advance time past TTL (15 minutes + 1 second)
      vi.advanceTimersByTime((15 * 60 * 1000) + 1000);

      // Run cleanup
      referenceStore.cleanup();

      // Reference should be expired
      expect(referenceStore.get(referenceId)).toBeUndefined();

      vi.useRealTimers();
    });

    it('should not expire references within TTL', () => {
      vi.useFakeTimers();
      const now = Date.now();
      vi.setSystemTime(now);

      const referenceId = referenceStore.create('Mail', 'mailbox', {
        type: 'named',
        element: 'mailbox',
        name: 'inbox',
        container: 'application'
      });

      // Advance time but stay within TTL (14 minutes)
      vi.advanceTimersByTime(14 * 60 * 1000);

      // Run cleanup
      referenceStore.cleanup();

      // Reference should still exist
      expect(referenceStore.get(referenceId)).toBeDefined();

      vi.useRealTimers();
    });

    it('should expire multiple references independently', () => {
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

      // Run cleanup
      referenceStore.cleanup();

      // ref1 should be expired, ref2 should still exist
      expect(referenceStore.get(ref1)).toBeUndefined();
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

    it('should extend TTL when touched', () => {
      vi.useFakeTimers();
      const now = Date.now();
      vi.setSystemTime(now);

      const referenceId = referenceStore.create('Mail', 'mailbox', {
        type: 'named',
        element: 'mailbox',
        name: 'inbox',
        container: 'application'
      });

      // Advance time 14 minutes (close to expiry)
      vi.advanceTimersByTime(14 * 60 * 1000);

      // Touch the reference (resets TTL)
      referenceStore.touch(referenceId);

      // Advance time another 10 minutes (24 minutes from creation, but 10 from touch)
      vi.advanceTimersByTime(10 * 60 * 1000);

      // Run cleanup
      referenceStore.cleanup();

      // Reference should still exist (touched 10 minutes ago)
      expect(referenceStore.get(referenceId)).toBeDefined();

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

  describe('Statistics Tracking', () => {
    it('should track total references created', async () => {
      const initialStats = referenceStore.getStatistics();

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

      const stats = referenceStore.getStatistics();
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

      const stats = referenceStore.getStatistics();
      expect(stats.activeReferences).toBeGreaterThan(0);
    });

    it('should update active count after cleanup', () => {
      vi.useFakeTimers();
      const now = Date.now();
      vi.setSystemTime(now);

      referenceStore.create('Mail', 'mailbox', {
        type: 'named',
        element: 'mailbox',
        name: 'inbox',
        container: 'application'
      });

      const statsBeforeCleanup = referenceStore.getStatistics();
      expect(statsBeforeCleanup.activeReferences).toBe(1);

      // Expire reference
      vi.advanceTimersByTime((15 * 60 * 1000) + 1000);
      referenceStore.cleanup();

      const statsAfterCleanup = referenceStore.getStatistics();
      expect(statsAfterCleanup.activeReferences).toBe(0);

      vi.useRealTimers();
    });

    it('should track last cleanup time', () => {
      vi.useFakeTimers();
      const now = Date.now();
      vi.setSystemTime(now);

      referenceStore.cleanup();

      const stats = referenceStore.getStatistics();
      expect(stats.lastCleanup).toBe(now);

      vi.useRealTimers();
    });
  });

  describe('Cleanup Mechanism', () => {
    it('should remove only expired references', () => {
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

      const ref3 = referenceStore.create('Finder', 'window', {
        type: 'element',
        element: 'window',
        index: 0,
        container: 'application'
      });

      // Advance time 10 minutes (ref1 at 20 min, ref2/ref3 at 10 min)
      vi.advanceTimersByTime(10 * 60 * 1000);

      referenceStore.cleanup();

      expect(referenceStore.get(ref1)).toBeUndefined();
      expect(referenceStore.get(ref2)).toBeDefined();
      expect(referenceStore.get(ref3)).toBeDefined();

      vi.useRealTimers();
    });

    it('should be safe to call cleanup multiple times', () => {
      referenceStore.cleanup();
      referenceStore.cleanup();
      referenceStore.cleanup();

      // Should not throw
      expect(true).toBe(true);
    });

    it('should handle cleanup with no references', () => {
      referenceStore.cleanup();

      const stats = referenceStore.getStatistics();
      expect(stats.activeReferences).toBe(0);
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
