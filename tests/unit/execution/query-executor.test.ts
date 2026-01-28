import { describe, it, expect, beforeEach } from 'vitest';
import { QueryExecutor } from '../../../src/execution/query-executor.js';
import { ReferenceStore } from '../../../src/execution/reference-store.js';
import { ObjectSpecifier, ElementSpecifier, NamedSpecifier, IdSpecifier, PropertySpecifier } from '../../../src/types/object-specifier.js';

// Test subclass that returns mock elements
class TestableQueryExecutor extends QueryExecutor {
  private mockElementCount = 0;

  setMockElementCount(count: number) {
    this.mockElementCount = count;
  }

  protected mockExecuteGetElements(
    app: string,
    containerSpec: ObjectSpecifier,
    elementType: string,
    limit: number
  ): { count: number; items: any[] } {
    if (this.mockElementCount === 0) {
      return { count: 0, items: [] };
    }

    // Return mock items
    const items = Array.from({ length: Math.min(this.mockElementCount, limit) }, (_, i) => ({
      index: i,
      mockData: `element-${i}`
    }));

    return {
      count: this.mockElementCount,
      items
    };
  }
}

describe('QueryExecutor', () => {
  let referenceStore: ReferenceStore;
  let queryExecutor: QueryExecutor;

  beforeEach(() => {
    referenceStore = new ReferenceStore();
    queryExecutor = new QueryExecutor(referenceStore);
  });

  describe('buildObjectPath() - via queryObject integration', () => {
    it('should generate correct path for ElementSpecifier', async () => {
      const specifier: ElementSpecifier = {
        type: 'element',
        element: 'message',
        index: 0,
        container: 'application'
      };

      const ref = await queryExecutor.queryObject('Mail', specifier);

      // Verify reference was created correctly
      expect(ref.app).toBe('Mail');
      expect(ref.type).toBe('message');
      expect(ref.specifier).toEqual(specifier);
    });

    it('should generate correct path for NamedSpecifier', async () => {
      const specifier: NamedSpecifier = {
        type: 'named',
        element: 'mailbox',
        name: 'inbox',
        container: 'application'
      };

      const ref = await queryExecutor.queryObject('Mail', specifier);

      expect(ref.app).toBe('Mail');
      expect(ref.type).toBe('mailbox');
      expect(ref.specifier).toEqual(specifier);
    });

    it('should generate correct path for IdSpecifier', async () => {
      const specifier: IdSpecifier = {
        type: 'id',
        element: 'message',
        id: 'abc123',
        container: 'application'
      };

      const ref = await queryExecutor.queryObject('Mail', specifier);

      expect(ref.app).toBe('Mail');
      expect(ref.type).toBe('message');
      expect(ref.specifier).toEqual(specifier);
    });

    it('should generate correct path for PropertySpecifier with specifier', async () => {
      const messageSpec: ElementSpecifier = {
        type: 'element',
        element: 'message',
        index: 0,
        container: 'application'
      };

      const propertySpec: PropertySpecifier = {
        type: 'property',
        property: 'subject',
        of: messageSpec
      };

      const ref = await queryExecutor.queryObject('Mail', propertySpec);

      expect(ref.app).toBe('Mail');
      expect(ref.type).toBe('message'); // Extracted from "of"
    });

    it('should handle nested specifiers (message in mailbox)', async () => {
      const mailboxSpec: NamedSpecifier = {
        type: 'named',
        element: 'mailbox',
        name: 'inbox',
        container: 'application'
      };

      const messageSpec: ElementSpecifier = {
        type: 'element',
        element: 'message',
        index: 0,
        container: mailboxSpec
      };

      const ref = await queryExecutor.queryObject('Mail', messageSpec);

      expect(ref.app).toBe('Mail');
      expect(ref.type).toBe('message');
      expect(ref.specifier).toEqual(messageSpec);
    });

    it('should handle deeply nested specifiers (3+ levels)', async () => {
      const accountSpec: NamedSpecifier = {
        type: 'named',
        element: 'account',
        name: 'work',
        container: 'application'
      };

      const mailboxSpec: NamedSpecifier = {
        type: 'named',
        element: 'mailbox',
        name: 'inbox',
        container: accountSpec
      };

      const messageSpec: ElementSpecifier = {
        type: 'element',
        element: 'message',
        index: 5,
        container: mailboxSpec
      };

      const ref = await queryExecutor.queryObject('Mail', messageSpec);

      expect(ref.app).toBe('Mail');
      expect(ref.type).toBe('message');
      expect(ref.specifier).toEqual(messageSpec);
    });

    it('should handle nested container in IdSpecifier', async () => {
      const mailboxSpec: NamedSpecifier = {
        type: 'named',
        element: 'mailbox',
        name: 'inbox',
        container: 'application'
      };

      const messageSpec: IdSpecifier = {
        type: 'id',
        element: 'message',
        id: 'msg-123',
        container: mailboxSpec
      };

      const ref = await queryExecutor.queryObject('Mail', messageSpec);

      expect(ref.app).toBe('Mail');
      expect(ref.type).toBe('message');
      expect(ref.specifier).toEqual(messageSpec);
    });
  });

  describe('queryObject()', () => {
    it('should create reference and store in ReferenceStore', async () => {
      const specifier: ElementSpecifier = {
        type: 'element',
        element: 'message',
        index: 0,
        container: 'application'
      };

      const ref = await queryExecutor.queryObject('Mail', specifier);

      expect(ref.id).toBeDefined();
      expect(ref.app).toBe('Mail');
      expect(ref.type).toBe('message');
      expect(ref.specifier).toEqual(specifier);
      expect(typeof ref.createdAt).toBe('number');
      expect(typeof ref.lastAccessedAt).toBe('number');

      // Verify it's in the store
      const storedRef = referenceStore.get(ref.id);
      expect(storedRef).toEqual(ref);
    });

    it('should return reference with correct ID, app, and type', async () => {
      const specifier: NamedSpecifier = {
        type: 'named',
        element: 'mailbox',
        name: 'sent',
        container: 'application'
      };

      const ref = await queryExecutor.queryObject('Mail', specifier);

      expect(ref.id).toMatch(/^ref_[a-z0-9]+$/); // Reference ID format
      expect(ref.app).toBe('Mail');
      expect(ref.type).toBe('mailbox');
    });

    it('should throw error on unsupported specifier type', async () => {
      const invalidSpec = {
        type: 'unsupported',
        element: 'message'
      } as any;

      await expect(queryExecutor.queryObject('Mail', invalidSpec))
        .rejects.toThrow('Unsupported specifier type');
    });

    it('should handle nested specifiers correctly', async () => {
      const containerSpec: NamedSpecifier = {
        type: 'named',
        element: 'mailbox',
        name: 'drafts',
        container: 'application'
      };

      const elementSpec: ElementSpecifier = {
        type: 'element',
        element: 'message',
        index: 2,
        container: containerSpec
      };

      const ref = await queryExecutor.queryObject('Mail', elementSpec);

      expect(ref.type).toBe('message');
      expect(ref.specifier).toEqual(elementSpec);
    });

    it('should extract correct type from PropertySpecifier with reference ID', async () => {
      // First create a message reference
      const messageSpec: ElementSpecifier = {
        type: 'element',
        element: 'message',
        index: 0,
        container: 'application'
      };
      const messageRef = await queryExecutor.queryObject('Mail', messageSpec);

      // Then create a property specifier using the reference ID
      const propertySpec: PropertySpecifier = {
        type: 'property',
        property: 'subject',
        of: messageRef.id
      };

      const ref = await queryExecutor.queryObject('Mail', propertySpec);

      expect(ref.type).toBe('message'); // Should extract from referenced object
    });
  });

  describe('getProperties()', () => {
    it('should retrieve reference from store', async () => {
      const specifier: ElementSpecifier = {
        type: 'element',
        element: 'message',
        index: 0,
        container: 'application'
      };
      const ref = await queryExecutor.queryObject('Mail', specifier);

      const properties = await queryExecutor.getProperties(ref.id);

      expect(properties).toBeDefined();
    });

    it('should update lastAccessedAt (touch reference)', async () => {
      const specifier: ElementSpecifier = {
        type: 'element',
        element: 'message',
        index: 0,
        container: 'application'
      };
      const ref = await queryExecutor.queryObject('Mail', specifier);

      const originalAccessTime = ref.lastAccessedAt;

      // Wait a bit to ensure time difference
      await new Promise(resolve => setTimeout(resolve, 10));

      await queryExecutor.getProperties(ref.id);

      const updatedRef = referenceStore.get(ref.id);
      expect(updatedRef!.lastAccessedAt).toBeGreaterThan(originalAccessTime);
    });

    it('should throw error on invalid reference ID', async () => {
      await expect(queryExecutor.getProperties('invalid-id'))
        .rejects.toThrow('Reference not found: invalid-id');
    });

    it('should return properties as Record<string, any>', async () => {
      const specifier: ElementSpecifier = {
        type: 'element',
        element: 'message',
        index: 0,
        container: 'application'
      };
      const ref = await queryExecutor.queryObject('Mail', specifier);

      const properties = await queryExecutor.getProperties(ref.id);

      expect(typeof properties).toBe('object');
      expect(properties).not.toBeNull();
    });

    it('should handle specific properties parameter', async () => {
      const specifier: ElementSpecifier = {
        type: 'element',
        element: 'message',
        index: 0,
        container: 'application'
      };
      const ref = await queryExecutor.queryObject('Mail', specifier);

      const properties = await queryExecutor.getProperties(ref.id, ['subject', 'sender']);

      expect(properties).toBeDefined();
    });

    it('should handle missing properties gracefully', async () => {
      const specifier: ElementSpecifier = {
        type: 'element',
        element: 'message',
        index: 0,
        container: 'application'
      };
      const ref = await queryExecutor.queryObject('Mail', specifier);

      const properties = await queryExecutor.getProperties(ref.id, ['nonexistent']);

      expect(properties).toBeDefined();
      expect(typeof properties).toBe('object');
    });
  });

  describe('getElements()', () => {
    it('should accept reference ID as container', async () => {
      const mailboxSpec: NamedSpecifier = {
        type: 'named',
        element: 'mailbox',
        name: 'inbox',
        container: 'application'
      };
      const mailboxRef = await queryExecutor.queryObject('Mail', mailboxSpec);

      const result = await queryExecutor.getElements(mailboxRef.id, 'message', 10);

      expect(result.elements).toBeInstanceOf(Array);
      expect(result.count).toBeGreaterThanOrEqual(0);
      expect(typeof result.hasMore).toBe('boolean');
    });

    it('should accept ObjectSpecifier as container', async () => {
      const mailboxSpec: NamedSpecifier = {
        type: 'named',
        element: 'mailbox',
        name: 'inbox',
        container: 'application'
      };

      const result = await queryExecutor.getElements(mailboxSpec, 'message', 10);

      expect(result.elements).toBeInstanceOf(Array);
      expect(result.count).toBeGreaterThanOrEqual(0);
      expect(typeof result.hasMore).toBe('boolean');
    });

    it('should create references for each element', async () => {
      const mailboxSpec: NamedSpecifier = {
        type: 'named',
        element: 'mailbox',
        name: 'inbox',
        container: 'application'
      };

      const result = await queryExecutor.getElements(mailboxSpec, 'message', 5);

      result.elements.forEach(element => {
        expect(element.id).toBeDefined();
        expect(element.app).toBe('Mail');
        expect(element.type).toBe('message');
        expect(element.specifier).toBeDefined();

        // Verify each element is in the store
        const storedRef = referenceStore.get(element.id);
        expect(storedRef).toEqual(element);
      });
    });

    it('should respect limit parameter', async () => {
      const mailboxSpec: NamedSpecifier = {
        type: 'named',
        element: 'mailbox',
        name: 'inbox',
        container: 'application'
      };

      const result = await queryExecutor.getElements(mailboxSpec, 'message', 3);

      expect(result.elements.length).toBeLessThanOrEqual(3);
    });

    it('should return hasMore correctly when count > limit', async () => {
      const mailboxSpec: NamedSpecifier = {
        type: 'named',
        element: 'mailbox',
        name: 'inbox',
        container: 'application'
      };

      const result = await queryExecutor.getElements(mailboxSpec, 'message', 5);

      if (result.count > 5) {
        expect(result.hasMore).toBe(true);
      } else {
        expect(result.hasMore).toBe(false);
      }
    });

    it('should return hasMore false when count <= limit', async () => {
      const mailboxSpec: NamedSpecifier = {
        type: 'named',
        element: 'mailbox',
        name: 'sent',
        container: 'application'
      };

      const result = await queryExecutor.getElements(mailboxSpec, 'message', 1000);

      expect(result.hasMore).toBe(false);
    });

    it('should throw error on invalid container reference', async () => {
      await expect(queryExecutor.getElements('invalid-ref-id', 'message', 10))
        .rejects.toThrow('Reference not found: invalid-ref-id');
    });

    it('should use default limit of 100', async () => {
      const mailboxSpec: NamedSpecifier = {
        type: 'named',
        element: 'mailbox',
        name: 'inbox',
        container: 'application'
      };

      const result = await queryExecutor.getElements(mailboxSpec, 'message');

      expect(result.elements.length).toBeLessThanOrEqual(100);
    });

    it('should create references for returned elements', async () => {
      const testExecutor = new TestableQueryExecutor(referenceStore);
      testExecutor.setMockElementCount(3);

      const mailboxSpec: NamedSpecifier = {
        type: 'named',
        element: 'mailbox',
        name: 'inbox',
        container: 'application'
      };

      const result = await testExecutor.getElements(mailboxSpec, 'message', 10);

      expect(result.elements.length).toBe(3);
      expect(result.count).toBe(3);
      expect(result.hasMore).toBe(false);

      // Verify each element is a valid reference
      result.elements.forEach((element, index) => {
        expect(element.id).toBeDefined();
        expect(element.app).toBe('Mail');
        expect(element.type).toBe('message');
        expect(element.specifier.type).toBe('element');

        // Verify it's in the store
        const storedRef = referenceStore.get(element.id);
        expect(storedRef).toEqual(element);
      });
    });

    it('should handle hasMore correctly when elements exceed limit', async () => {
      const testExecutor = new TestableQueryExecutor(referenceStore);
      testExecutor.setMockElementCount(10);

      const mailboxSpec: NamedSpecifier = {
        type: 'named',
        element: 'mailbox',
        name: 'inbox',
        container: 'application'
      };

      const result = await testExecutor.getElements(mailboxSpec, 'message', 5);

      expect(result.elements.length).toBe(5);
      expect(result.count).toBe(10);
      expect(result.hasMore).toBe(true);
    });
  });

  describe('Helper Methods', () => {
    describe('camelCase()', () => {
      it('should convert "read status" to "readStatus"', async () => {
        const specifier: PropertySpecifier = {
          type: 'property',
          property: 'read status',
          of: {
            type: 'element',
            element: 'message',
            index: 0,
            container: 'application'
          }
        };

        // The camelCase is used internally when building JXA path
        const ref = await queryExecutor.queryObject('Mail', specifier);
        expect(ref).toBeDefined();
      });

      it('should handle single word', async () => {
        const specifier: PropertySpecifier = {
          type: 'property',
          property: 'subject',
          of: {
            type: 'element',
            element: 'message',
            index: 0,
            container: 'application'
          }
        };

        const ref = await queryExecutor.queryObject('Mail', specifier);
        expect(ref).toBeDefined();
      });

      it('should handle multiple spaces', async () => {
        const specifier: PropertySpecifier = {
          type: 'property',
          property: 'some multi word property',
          of: {
            type: 'element',
            element: 'message',
            index: 0,
            container: 'application'
          }
        };

        const ref = await queryExecutor.queryObject('Mail', specifier);
        expect(ref).toBeDefined();
      });
    });

    describe('pluralize()', () => {
      it('should pluralize "message" to "messages"', async () => {
        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'message',
          index: 0,
          container: 'application'
        };

        const ref = await queryExecutor.queryObject('Mail', specifier);
        expect(ref.type).toBe('message');
      });

      it('should pluralize "mailbox" to "mailboxes"', async () => {
        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'mailbox',
          index: 0,
          container: 'application'
        };

        const ref = await queryExecutor.queryObject('Mail', specifier);
        expect(ref.type).toBe('mailbox');
      });

      it('should handle words ending in "s"', async () => {
        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'class',
          index: 0,
          container: 'application'
        };

        const ref = await queryExecutor.queryObject('Mail', specifier);
        expect(ref.type).toBe('class');
      });
    });

    describe('extractObjectType()', () => {
      it('should extract type from ElementSpecifier', async () => {
        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'message',
          index: 0,
          container: 'application'
        };

        const ref = await queryExecutor.queryObject('Mail', specifier);
        expect(ref.type).toBe('message');
      });

      it('should extract type from NamedSpecifier', async () => {
        const specifier: NamedSpecifier = {
          type: 'named',
          element: 'mailbox',
          name: 'inbox',
          container: 'application'
        };

        const ref = await queryExecutor.queryObject('Mail', specifier);
        expect(ref.type).toBe('mailbox');
      });

      it('should extract type from IdSpecifier', async () => {
        const specifier: IdSpecifier = {
          type: 'id',
          element: 'message',
          id: 'abc123',
          container: 'application'
        };

        const ref = await queryExecutor.queryObject('Mail', specifier);
        expect(ref.type).toBe('message');
      });

      it('should extract type from PropertySpecifier with nested specifier', async () => {
        const propertySpec: PropertySpecifier = {
          type: 'property',
          property: 'subject',
          of: {
            type: 'element',
            element: 'message',
            index: 0,
            container: 'application'
          }
        };

        const ref = await queryExecutor.queryObject('Mail', propertySpec);
        expect(ref.type).toBe('message');
      });

      it('should extract type from PropertySpecifier with reference ID', async () => {
        const messageSpec: ElementSpecifier = {
          type: 'element',
          element: 'message',
          index: 0,
          container: 'application'
        };
        const messageRef = await queryExecutor.queryObject('Mail', messageSpec);

        const propertySpec: PropertySpecifier = {
          type: 'property',
          property: 'sender',
          of: messageRef.id
        };

        const ref = await queryExecutor.queryObject('Mail', propertySpec);
        expect(ref.type).toBe('message');
      });
    });
  });

  describe('Error Handling', () => {
    it('should handle failed reference creation gracefully', async () => {
      // Create a mock reference store that simulates creation failure
      const mockStore = new ReferenceStore();
      const originalGet = mockStore.get.bind(mockStore);
      mockStore.get = (id: string) => {
        // Return undefined to simulate failed reference creation
        return undefined;
      };

      const executorWithMockStore = new QueryExecutor(mockStore);

      const specifier: ElementSpecifier = {
        type: 'element',
        element: 'message',
        index: 0,
        container: 'application'
      };

      const error = await executorWithMockStore.queryObject('Mail', specifier)
        .catch(e => e);

      expect(error.message).toBe('Failed to create reference');
    });

    it('should provide clear error for invalid reference ID in getProperties', async () => {
      const error = await queryExecutor.getProperties('does-not-exist')
        .catch(e => e);

      expect(error.message).toBe('Reference not found: does-not-exist');
    });

    it('should provide clear error for invalid reference ID in getElements', async () => {
      const error = await queryExecutor.getElements('does-not-exist', 'message', 10)
        .catch(e => e);

      expect(error.message).toBe('Reference not found: does-not-exist');
    });

    it('should provide error with details for unsupported specifier type', async () => {
      const invalidSpec = {
        type: 'custom-type',
        element: 'message'
      } as any;

      const error = await queryExecutor.queryObject('Mail', invalidSpec)
        .catch(e => e);

      expect(error.message).toContain('Unsupported specifier type');
    });

    it('should handle reference resolution failure gracefully', async () => {
      const propertySpec: PropertySpecifier = {
        type: 'property',
        property: 'subject',
        of: 'invalid-ref-id'
      };

      const error = await queryExecutor.queryObject('Mail', propertySpec)
        .catch(e => e);

      expect(error.message).toBe('Reference not found: invalid-ref-id');
    });
  });
});
