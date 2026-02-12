/**
 * Concurrent and Edge Case Tests for ReferenceStore
 *
 * Tests concurrent reference creation and retrieval to ensure
 * thread-safety and proper handling of simultaneous operations.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { ReferenceStore } from '../../../src/execution/reference-store.js';
import type { ObjectSpecifier } from '../../../src/types/object-specifier.js';

describe('ReferenceStore - Concurrent Operations', () => {
  let store: ReferenceStore;

  beforeEach(() => {
    store = new ReferenceStore();
  });

  afterEach(() => {
    store.stopCleanup();
  });

  describe('Concurrent Reference Creation', () => {
    it('should create unique IDs when called multiple times simultaneously', async () => {
      const specifier: ObjectSpecifier = {
        type: 'element',
        element: 'window',
        index: 0,
        container: 'application'
      };

      // Create 100 references simultaneously using Promise.all
      const promises = Array.from({ length: 100 }, () =>
        Promise.resolve(store.create('com.apple.finder', 'window', specifier))
      );

      const ids = await Promise.all(promises);

      // All IDs should be unique
      const uniqueIds = new Set(ids);
      expect(uniqueIds.size).toBe(100);

      // All IDs should have correct format
      ids.forEach(id => {
        expect(id).toMatch(/^ref_[a-z0-9-]+$/);
      });
    });

    it('should handle rapid sequential creation without conflicts', () => {
      const specifier: ObjectSpecifier = {
        type: 'element',
        element: 'message',
        index: 0,
        container: 'application'
      };

      const ids: string[] = [];

      // Rapidly create 500 references
      for (let i = 0; i < 500; i++) {
        const id = store.create('com.apple.mail', 'message', specifier);
        ids.push(id);
      }

      // All IDs should be unique
      const uniqueIds = new Set(ids);
      expect(uniqueIds.size).toBe(500);

      // All should be retrievable
      ids.forEach(id => {
        const ref = store.get(id);
        expect(ref).toBeDefined();
        expect(ref?.id).toBe(id);
      });
    });

    it('should handle concurrent creation from different "apps"', async () => {
      const apps = [
        'com.apple.finder',
        'com.apple.mail',
        'com.apple.safari',
        'com.apple.calendar',
        'com.apple.notes'
      ];

      const specifier: ObjectSpecifier = {
        type: 'element',
        element: 'window',
        index: 0,
        container: 'application'
      };

      // Create 20 references per app simultaneously
      const promises: Promise<string>[] = [];
      for (const app of apps) {
        for (let i = 0; i < 20; i++) {
          promises.push(
            Promise.resolve(store.create(app, 'window', specifier))
          );
        }
      }

      const ids = await Promise.all(promises);

      // All 100 IDs should be unique
      const uniqueIds = new Set(ids);
      expect(uniqueIds.size).toBe(100);

      // Stats should reflect correct per-app counts
      const stats = store.getStats();
      expect(stats.totalReferences).toBe(100);
      apps.forEach(app => {
        expect(stats.referencesPerApp[app]).toBe(20);
      });
    });

    it('should maintain data integrity under concurrent access', async () => {
      const specifiers: ObjectSpecifier[] = [
        { type: 'element', element: 'window', index: 0, container: 'application' },
        { type: 'named', element: 'document', name: 'test.txt', container: 'application' },
        { type: 'id', element: 'message', id: 'msg-123', container: 'application' }
      ];

      // Create references with different specifiers concurrently
      const promises = specifiers.flatMap((spec, i) =>
        Array.from({ length: 10 }, () =>
          Promise.resolve(store.create(`app-${i}`, spec.element, spec))
        )
      );

      const ids = await Promise.all(promises);

      // Verify all references maintain correct specifier associations
      ids.forEach((id, index) => {
        const ref = store.get(id);
        expect(ref).toBeDefined();

        const specIndex = Math.floor(index / 10);
        expect(ref?.specifier).toEqual(specifiers[specIndex]);
        expect(ref?.app).toBe(`app-${specIndex}`);
      });
    });
  });

  describe('Concurrent Creation and Retrieval', () => {
    it('should handle interleaved create and get operations', async () => {
      const specifier: ObjectSpecifier = {
        type: 'element',
        element: 'window',
        index: 0,
        container: 'application'
      };

      const createdIds: string[] = [];

      // Interleave create and get operations
      for (let i = 0; i < 50; i++) {
        const id = store.create('com.apple.finder', 'window', specifier);
        createdIds.push(id);

        // Immediately verify retrieval
        const ref = store.get(id);
        expect(ref).toBeDefined();
        expect(ref?.id).toBe(id);

        // Also try to get a previous ID (if exists)
        if (i > 0) {
          const prevRef = store.get(createdIds[i - 1]);
          expect(prevRef).toBeDefined();
        }
      }

      expect(store.getStats().totalReferences).toBe(50);
    });

    it('should handle concurrent touch operations', async () => {
      const specifier: ObjectSpecifier = {
        type: 'element',
        element: 'window',
        index: 0,
        container: 'application'
      };

      // Create some references
      const ids = Array.from({ length: 10 }, () =>
        store.create('com.apple.finder', 'window', specifier)
      );

      // Touch all of them concurrently
      const touchPromises = ids.flatMap(id =>
        // Touch each ID multiple times
        Array.from({ length: 5 }, () =>
          Promise.resolve(store.touch(id))
        )
      );

      await Promise.all(touchPromises);

      // All references should still be valid
      ids.forEach(id => {
        const ref = store.get(id);
        expect(ref).toBeDefined();
      });
    });
  });

  describe('Concurrent Creation and Eviction', () => {
    it('should handle eviction while creating new references', async () => {
      const smallStore = new ReferenceStore(10);
      const specifier: ObjectSpecifier = {
        type: 'element',
        element: 'window',
        index: 0,
        container: 'application'
      };

      // Create initial references at capacity
      const oldIds: string[] = [];
      for (let i = 0; i < 10; i++) {
        oldIds.push(smallStore.create('com.apple.finder', 'window', specifier));
      }

      // Wait a bit so new references have different timestamps
      await new Promise(resolve => setTimeout(resolve, 10));

      // Create 10 more references concurrently (will trigger evictions)
      const createPromises: Promise<string>[] = [];
      for (let i = 0; i < 10; i++) {
        createPromises.push(
          Promise.resolve(smallStore.create('com.apple.finder', 'window', specifier))
        );
      }

      const newIds = await Promise.all(createPromises);

      // Store should be at capacity
      expect(smallStore.getStats().totalReferences).toBe(10);

      // New references should exist
      newIds.forEach(id => {
        const ref = smallStore.get(id);
        expect(ref).toBeDefined();
      });
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty string app name', () => {
      const specifier: ObjectSpecifier = {
        type: 'element',
        element: 'window',
        index: 0,
        container: 'application'
      };

      const id = store.create('', 'window', specifier);
      const ref = store.get(id);

      expect(ref).toBeDefined();
      expect(ref?.app).toBe('');
    });

    it('should handle empty string type', () => {
      const specifier: ObjectSpecifier = {
        type: 'element',
        element: 'window',
        index: 0,
        container: 'application'
      };

      const id = store.create('com.apple.finder', '', specifier);
      const ref = store.get(id);

      expect(ref).toBeDefined();
      expect(ref?.type).toBe('');
    });

    it('should handle complex nested specifier structures', () => {
      const complexSpecifier: ObjectSpecifier = {
        type: 'element',
        element: 'message',
        index: 0,
        container: {
          type: 'named',
          element: 'mailbox',
          name: 'inbox',
          container: {
            type: 'id',
            element: 'account',
            id: 'acc-123',
            container: 'application'
          }
        }
      };

      const id = store.create('com.apple.mail', 'message', complexSpecifier);
      const ref = store.get(id);

      expect(ref).toBeDefined();
      expect(ref?.specifier).toEqual(complexSpecifier);
    });

    it('should handle very long app names', () => {
      const longAppName = 'com.example.' + 'a'.repeat(1000);
      const specifier: ObjectSpecifier = {
        type: 'element',
        element: 'window',
        index: 0,
        container: 'application'
      };

      const id = store.create(longAppName, 'window', specifier);
      const ref = store.get(id);

      expect(ref).toBeDefined();
      expect(ref?.app).toBe(longAppName);
    });

    it('should handle very long type names', () => {
      const longType = 'type_' + 'x'.repeat(1000);
      const specifier: ObjectSpecifier = {
        type: 'element',
        element: 'window',
        index: 0,
        container: 'application'
      };

      const id = store.create('com.apple.finder', longType, specifier);
      const ref = store.get(id);

      expect(ref).toBeDefined();
      expect(ref?.type).toBe(longType);
    });

    it('should handle specifier with negative index', () => {
      const specifier: ObjectSpecifier = {
        type: 'element',
        element: 'window',
        index: -1,
        container: 'application'
      };

      const id = store.create('com.apple.finder', 'window', specifier);
      const ref = store.get(id);

      expect(ref).toBeDefined();
      expect((ref?.specifier as any).index).toBe(-1);
    });

    it('should handle specifier with very large index', () => {
      const specifier: ObjectSpecifier = {
        type: 'element',
        element: 'window',
        index: Number.MAX_SAFE_INTEGER,
        container: 'application'
      };

      const id = store.create('com.apple.finder', 'window', specifier);
      const ref = store.get(id);

      expect(ref).toBeDefined();
      expect((ref?.specifier as any).index).toBe(Number.MAX_SAFE_INTEGER);
    });

    it('should handle special characters in app names', () => {
      const specifier: ObjectSpecifier = {
        type: 'element',
        element: 'window',
        index: 0,
        container: 'application'
      };

      const specialApps = [
        'com.apple.finder',
        'com.company-name.app',
        'app_with_underscores',
        'APP.WITH.CAPS'
      ];

      specialApps.forEach(appName => {
        const id = store.create(appName, 'window', specifier);
        const ref = store.get(id);
        expect(ref?.app).toBe(appName);
      });
    });

    it('should maintain reference count accuracy after many operations', () => {
      const specifier: ObjectSpecifier = {
        type: 'element',
        element: 'window',
        index: 0,
        container: 'application'
      };

      // Create many references
      const ids: string[] = [];
      for (let i = 0; i < 100; i++) {
        ids.push(store.create('com.apple.finder', 'window', specifier));
      }

      expect(store.getStats().totalReferences).toBe(100);

      // Clear and verify
      store.clear();
      expect(store.getStats().totalReferences).toBe(0);

      // Create more
      for (let i = 0; i < 50; i++) {
        store.create('com.apple.mail', 'message', specifier);
      }

      expect(store.getStats().totalReferences).toBe(50);
    });
  });

  describe('UUID Uniqueness Guarantee', () => {
    it('should use crypto.randomUUID for ID generation', () => {
      const specifier: ObjectSpecifier = {
        type: 'element',
        element: 'window',
        index: 0,
        container: 'application'
      };

      const id = store.create('com.apple.finder', 'window', specifier);

      // UUID format: ref_xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
      expect(id).toMatch(/^ref_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    });

    it('should generate statistically unique IDs over large sample', () => {
      const specifier: ObjectSpecifier = {
        type: 'element',
        element: 'window',
        index: 0,
        container: 'application'
      };

      const ids = new Set<string>();
      const count = 10000;

      for (let i = 0; i < count; i++) {
        const id = store.create('com.apple.finder', 'window', specifier);
        if (ids.has(id)) {
          expect.fail(`Duplicate ID found: ${id}`);
        }
        ids.add(id);
      }

      expect(ids.size).toBe(count);
      store.clear();
    });
  });
});
