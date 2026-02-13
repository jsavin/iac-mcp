import { describe, it, expect, beforeEach } from 'vitest';
import { QueryExecutor } from '../../../src/execution/query-executor.js';
import { ReferenceStore } from '../../../src/execution/reference-store.js';
import { ObjectSpecifier, ElementSpecifier, NamedSpecifier, IdSpecifier, PropertySpecifier } from '../../../src/types/object-specifier.js';

// Test subclass that returns mock elements and exposes private methods for testing
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

  /**
   * Expose pluralize method for direct testing
   */
  public testPluralize(str: string): string {
    return (this as any).pluralize(str);
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

      expect(ref.id).toMatch(/^ref_[a-f0-9-]+$/); // Reference ID format (UUID)
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

      const result = await queryExecutor.getElements(mailboxRef.id, 'message', undefined, 10);

      expect(result.elements).toBeInstanceOf(Array);
      expect(result.count).toBeGreaterThanOrEqual(0);
      expect(typeof result.hasMore).toBe('boolean');
    });

    it('should accept ObjectSpecifier as container with app parameter', async () => {
      const mailboxSpec: NamedSpecifier = {
        type: 'named',
        element: 'mailbox',
        name: 'inbox',
        container: 'application'
      };

      const result = await queryExecutor.getElements(mailboxSpec, 'message', 'Mail', 10);

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

      const result = await queryExecutor.getElements(mailboxSpec, 'message', 'Mail', 5);

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

      const result = await queryExecutor.getElements(mailboxSpec, 'message', 'Mail', 3);

      expect(result.elements.length).toBeLessThanOrEqual(3);
    });

    it('should return hasMore correctly when count > limit', async () => {
      const mailboxSpec: NamedSpecifier = {
        type: 'named',
        element: 'mailbox',
        name: 'inbox',
        container: 'application'
      };

      const result = await queryExecutor.getElements(mailboxSpec, 'message', 'Mail', 5);

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

      const result = await queryExecutor.getElements(mailboxSpec, 'message', 'Mail', 1000);

      expect(result.hasMore).toBe(false);
    });

    it('should throw error on invalid container reference', async () => {
      await expect(queryExecutor.getElements('ref_invalid-ref-id', 'message', undefined, 10))
        .rejects.toThrow('Reference not found: ref_invalid-ref-id');
    });

    it('should use default limit of 100', async () => {
      const mailboxSpec: NamedSpecifier = {
        type: 'named',
        element: 'mailbox',
        name: 'inbox',
        container: 'application'
      };

      const result = await queryExecutor.getElements(mailboxSpec, 'message', 'Mail');

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

      const result = await testExecutor.getElements(mailboxSpec, 'message', 'Mail', 10);

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

      const result = await testExecutor.getElements(mailboxSpec, 'message', 'Mail', 5);

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
      let testExecutor: TestableQueryExecutor;

      beforeEach(() => {
        testExecutor = new TestableQueryExecutor(referenceStore);
      });

      // Basic pluralization (default rule: add 's')
      it('should pluralize "message" to "messages"', () => {
        expect(testExecutor.testPluralize('message')).toBe('messages');
      });

      it('should pluralize "window" to "windows"', () => {
        expect(testExecutor.testPluralize('window')).toBe('windows');
      });

      // Words ending in 'x' -> add 'es'
      it('should pluralize "mailbox" to "mailboxes"', () => {
        expect(testExecutor.testPluralize('mailbox')).toBe('mailboxes');
      });

      it('should pluralize "box" to "boxes"', () => {
        expect(testExecutor.testPluralize('box')).toBe('boxes');
      });

      // Words ending in 's' -> add 'es'
      it('should pluralize "class" to "classes"', () => {
        expect(testExecutor.testPluralize('class')).toBe('classes');
      });

      it('should pluralize "bus" to "buses"', () => {
        expect(testExecutor.testPluralize('bus')).toBe('buses');
      });

      // Words ending in 'ch', 'sh' -> add 'es'
      it('should pluralize "branch" to "branches"', () => {
        expect(testExecutor.testPluralize('branch')).toBe('branches');
      });

      it('should pluralize "brush" to "brushes"', () => {
        expect(testExecutor.testPluralize('brush')).toBe('brushes');
      });

      // Words ending in 'z' -> add 'es'
      it('should pluralize "quiz" to "quizzes"', () => {
        expect(testExecutor.testPluralize('quiz')).toBe('quizzes');
      });

      // Words ending in consonant + 'y' -> replace 'y' with 'ies'
      it('should pluralize "category" to "categories"', () => {
        expect(testExecutor.testPluralize('category')).toBe('categories');
      });

      it('should pluralize "story" to "stories"', () => {
        expect(testExecutor.testPluralize('story')).toBe('stories');
      });

      it('should pluralize "entry" to "entries"', () => {
        expect(testExecutor.testPluralize('entry')).toBe('entries');
      });

      // Words ending in vowel + 'y' -> add 's' (not 'ies')
      it('should pluralize "key" to "keys"', () => {
        expect(testExecutor.testPluralize('key')).toBe('keys');
      });

      it('should pluralize "day" to "days"', () => {
        expect(testExecutor.testPluralize('day')).toBe('days');
      });

      it('should pluralize "display" to "displays"', () => {
        expect(testExecutor.testPluralize('display')).toBe('displays');
      });

      // Irregular plurals (macOS app terms)
      it('should pluralize "person" to "people"', () => {
        expect(testExecutor.testPluralize('person')).toBe('people');
      });

      it('should pluralize "child" to "children"', () => {
        expect(testExecutor.testPluralize('child')).toBe('children');
      });

      it('should pluralize "mouse" to "mice"', () => {
        expect(testExecutor.testPluralize('mouse')).toBe('mice');
      });

      it('should pluralize "index" to "indices"', () => {
        expect(testExecutor.testPluralize('index')).toBe('indices');
      });

      it('should pluralize "datum" to "data"', () => {
        expect(testExecutor.testPluralize('datum')).toBe('data');
      });

      it('should pluralize "medium" to "media"', () => {
        expect(testExecutor.testPluralize('medium')).toBe('media');
      });

      // Words that are same in singular and plural
      it('should keep "series" as "series"', () => {
        expect(testExecutor.testPluralize('series')).toBe('series');
      });

      it('should keep "species" as "species"', () => {
        expect(testExecutor.testPluralize('species')).toBe('species');
      });

      it('should keep "fish" as "fish"', () => {
        expect(testExecutor.testPluralize('fish')).toBe('fish');
      });

      it('should keep "data" as "data"', () => {
        expect(testExecutor.testPluralize('data')).toBe('data');
      });

      // Words ending in 'f' or 'fe' -> 'ves'
      it('should pluralize "leaf" to "leaves"', () => {
        expect(testExecutor.testPluralize('leaf')).toBe('leaves');
      });

      it('should pluralize "knife" to "knives"', () => {
        expect(testExecutor.testPluralize('knife')).toBe('knives');
      });

      it('should pluralize "life" to "lives"', () => {
        expect(testExecutor.testPluralize('life')).toBe('lives');
      });

      // Exceptions for 'f' words that just add 's'
      it('should pluralize "roof" to "roofs"', () => {
        expect(testExecutor.testPluralize('roof')).toBe('roofs');
      });

      it('should pluralize "chief" to "chiefs"', () => {
        expect(testExecutor.testPluralize('chief')).toBe('chiefs');
      });

      // Words ending in 'o' - varies
      it('should pluralize "hero" to "heroes"', () => {
        expect(testExecutor.testPluralize('hero')).toBe('heroes');
      });

      it('should pluralize "photo" to "photos"', () => {
        expect(testExecutor.testPluralize('photo')).toBe('photos');
      });

      it('should pluralize "video" to "videos"', () => {
        expect(testExecutor.testPluralize('video')).toBe('videos');
      });

      // Already plural patterns (should not double-pluralize)
      it('should keep "categories" as "categories"', () => {
        expect(testExecutor.testPluralize('categories')).toBe('categories');
      });

      it('should keep "boxes" as "boxes"', () => {
        expect(testExecutor.testPluralize('boxes')).toBe('boxes');
      });

      it('should keep "brushes" as "brushes"', () => {
        expect(testExecutor.testPluralize('brushes')).toBe('brushes');
      });

      // Case insensitivity for irregular lookups
      it('should handle case-insensitive lookups for "Person"', () => {
        expect(testExecutor.testPluralize('Person')).toBe('people');
      });

      it('should handle case-insensitive lookups for "CHILD"', () => {
        expect(testExecutor.testPluralize('CHILD')).toBe('children');
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

      expect(error.message).toContain('Reference not found: does-not-exist');
    });

    it('should provide clear error for invalid reference ID in getElements', async () => {
      const error = await queryExecutor.getElements('ref_does-not-exist', 'message', undefined, 10)
        .catch(e => e);

      expect(error.message).toContain('Reference not found: ref_does-not-exist');
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

      expect(error.message).toContain('Reference not found: invalid-ref-id');
    });
  });

  describe('JXA Execution with JXAExecutor', () => {
    // Mock JXAExecutor for testing
    const createMockJXAExecutor = (mockResponse: { exitCode: number; stdout: string; stderr: string; timedOut?: boolean }) => ({
      execute: async (_script: string) => mockResponse
    });

    describe('getProperties() with JXA execution', () => {
      it('should generate correct JXA for all properties', async () => {
        let capturedScript = '';
        const mockExecutor = {
          execute: async (script: string) => {
            capturedScript = script;
            return {
              exitCode: 0,
              stdout: JSON.stringify({ subject: 'Test', sender: 'user@test.com' }),
              stderr: ''
            };
          }
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'message',
          index: 0,
          container: 'application'
        };
        const ref = await executorWithJxa.queryObject('Mail', specifier);

        const properties = await executorWithJxa.getProperties(ref.id);

        // Verify JXA was generated and executed
        expect(capturedScript).toContain('Application("Mail")');
        expect(capturedScript).toContain('properties()');
        expect(capturedScript).toContain('JSON.stringify');
        // Verify properties returned
        expect(properties).toEqual({ subject: 'Test', sender: 'user@test.com' });
      });

      it('should generate correct JXA for specific properties', async () => {
        let capturedScript = '';
        const mockExecutor = {
          execute: async (script: string) => {
            capturedScript = script;
            return {
              exitCode: 0,
              stdout: JSON.stringify({ subject: 'Test Subject' }),
              stderr: ''
            };
          }
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const specifier: NamedSpecifier = {
          type: 'named',
          element: 'mailbox',
          name: 'INBOX',
          container: 'application'
        };
        const ref = await executorWithJxa.queryObject('Mail', specifier);

        const properties = await executorWithJxa.getProperties(ref.id, ['subject']);

        // Verify specific property access in JXA
        expect(capturedScript).toContain('subject()');
        expect(properties).toEqual({ subject: 'Test Subject' });
      });

      it('should generate correct JXA for multiple specific properties', async () => {
        let capturedScript = '';
        const mockExecutor = {
          execute: async (script: string) => {
            capturedScript = script;
            return {
              exitCode: 0,
              stdout: JSON.stringify({ subject: 'Test', sender: 'user@test.com' }),
              stderr: ''
            };
          }
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'message',
          index: 0,
          container: 'application'
        };
        const ref = await executorWithJxa.queryObject('Mail', specifier);

        await executorWithJxa.getProperties(ref.id, ['subject', 'sender']);

        // Verify both properties are accessed
        expect(capturedScript).toContain('subject()');
        expect(capturedScript).toContain('sender()');
      });

      it('should handle APP_NOT_FOUND error', async () => {
        const mockExecutor = createMockJXAExecutor({
          exitCode: 1,
          stdout: '',
          stderr: "Error: Application can't be found."
        });

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'message',
          index: 0,
          container: 'application'
        };
        const ref = await executorWithJxa.queryObject('NonExistentApp', specifier);

        const error = await executorWithJxa.getProperties(ref.id).catch(e => e);

        expect(error.message).toContain('Application not found');
      });

      it('should handle PERMISSION_DENIED error', async () => {
        const mockExecutor = createMockJXAExecutor({
          exitCode: 1,
          stdout: '',
          stderr: 'Error: Not authorized to send Apple events to Mail.'
        });

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'message',
          index: 0,
          container: 'application'
        };
        const ref = await executorWithJxa.queryObject('Mail', specifier);

        const error = await executorWithJxa.getProperties(ref.id).catch(e => e);

        expect(error.message).toContain('Permission denied');
      });

      it('should handle INVALID_PARAM error (object not found)', async () => {
        const mockExecutor = createMockJXAExecutor({
          exitCode: 1,
          stdout: '',
          stderr: "Error: Can't get object."
        });

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'message',
          index: 999,
          container: 'application'
        };
        const ref = await executorWithJxa.queryObject('Mail', specifier);

        const error = await executorWithJxa.getProperties(ref.id).catch(e => e);

        expect(error.message).toContain('Object not found');
      });

      it('should handle TIMEOUT error', async () => {
        const mockExecutor = createMockJXAExecutor({
          exitCode: 1,
          stdout: '',
          stderr: '',
          timedOut: true
        });

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'message',
          index: 0,
          container: 'application'
        };
        const ref = await executorWithJxa.queryObject('Mail', specifier);

        const error = await executorWithJxa.getProperties(ref.id).catch(e => e);

        expect(error.message).toContain('timed out');
      });
    });

    describe('getElements() with JXA execution', () => {
      it('should generate correct getElements JXA with limit', async () => {
        let capturedScript = '';
        const mockExecutor = {
          execute: async (script: string) => {
            capturedScript = script;
            return {
              exitCode: 0,
              stdout: JSON.stringify({ count: 5, items: [{ index: 0 }, { index: 1 }, { index: 2 }] }),
              stderr: ''
            };
          }
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const mailboxSpec: NamedSpecifier = {
          type: 'named',
          element: 'mailbox',
          name: 'INBOX',
          container: 'application'
        };
        const ref = await executorWithJxa.queryObject('Mail', mailboxSpec);

        const result = await executorWithJxa.getElements(ref.id, 'message', undefined, 3);

        // Verify JXA contains limit
        expect(capturedScript).toContain('Math.min');
        expect(capturedScript).toContain('3');
        expect(capturedScript).toContain('messages');
        // Verify result
        expect(result.count).toBe(5);
        expect(result.elements.length).toBe(3);
        expect(result.hasMore).toBe(true);
      });

      it('should return hasMore=true when count > limit', async () => {
        const mockExecutor = {
          execute: async () => ({
            exitCode: 0,
            stdout: JSON.stringify({ count: 100, items: [{ index: 0 }, { index: 1 }] }),
            stderr: ''
          })
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const mailboxSpec: NamedSpecifier = {
          type: 'named',
          element: 'mailbox',
          name: 'INBOX',
          container: 'application'
        };
        const ref = await executorWithJxa.queryObject('Mail', mailboxSpec);

        const result = await executorWithJxa.getElements(ref.id, 'message', undefined, 2);

        expect(result.hasMore).toBe(true);
        expect(result.count).toBe(100);
      });

      it('should return hasMore=false when count <= limit', async () => {
        const mockExecutor = {
          execute: async () => ({
            exitCode: 0,
            stdout: JSON.stringify({ count: 2, items: [{ index: 0 }, { index: 1 }] }),
            stderr: ''
          })
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const mailboxSpec: NamedSpecifier = {
          type: 'named',
          element: 'mailbox',
          name: 'INBOX',
          container: 'application'
        };
        const ref = await executorWithJxa.queryObject('Mail', mailboxSpec);

        const result = await executorWithJxa.getElements(ref.id, 'message', undefined, 10);

        expect(result.hasMore).toBe(false);
        expect(result.count).toBe(2);
      });

      it('should handle APP_NOT_FOUND error in getElements', async () => {
        const mockExecutor = createMockJXAExecutor({
          exitCode: 1,
          stdout: '',
          stderr: "Error: Application can't be found."
        });

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const mailboxSpec: NamedSpecifier = {
          type: 'named',
          element: 'mailbox',
          name: 'INBOX',
          container: 'application'
        };
        const ref = await executorWithJxa.queryObject('NonExistentApp', mailboxSpec);

        const error = await executorWithJxa.getElements(ref.id, 'message', undefined, 10).catch(e => e);

        expect(error.message).toContain('Application not found');
      });

      it('should handle direct specifier with app parameter', async () => {
        let capturedScript = '';
        const mockExecutor = {
          execute: async (script: string) => {
            capturedScript = script;
            return {
              exitCode: 0,
              stdout: JSON.stringify({ count: 2, items: [{ index: 0 }, { index: 1 }] }),
              stderr: ''
            };
          }
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const mailboxSpec: NamedSpecifier = {
          type: 'named',
          element: 'mailbox',
          name: 'INBOX',
          container: 'application'
        };

        const result = await executorWithJxa.getElements(mailboxSpec, 'message', 'Mail', 10);

        expect(capturedScript).toContain('Application("Mail")');
        expect(result.count).toBe(2);
        expect(result.elements.length).toBe(2);
      });

      it('should create references for each returned element', async () => {
        const mockExecutor = {
          execute: async () => ({
            exitCode: 0,
            stdout: JSON.stringify({ count: 3, items: [{ index: 0 }, { index: 1 }, { index: 2 }] }),
            stderr: ''
          })
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const mailboxSpec: NamedSpecifier = {
          type: 'named',
          element: 'mailbox',
          name: 'INBOX',
          container: 'application'
        };
        const ref = await executorWithJxa.queryObject('Mail', mailboxSpec);

        const result = await executorWithJxa.getElements(ref.id, 'message', undefined, 10);

        expect(result.elements.length).toBe(3);
        result.elements.forEach((element, index) => {
          expect(element.id).toMatch(/^ref_/);
          expect(element.app).toBe('Mail');
          expect(element.type).toBe('message');
          expect(element.specifier.type).toBe('element');
          expect((element.specifier as ElementSpecifier).index).toBe(index);
          // Verify stored in reference store
          expect(referenceStore.get(element.id)).toEqual(element);
        });
      });
    });

    describe('Backward compatibility (no JXAExecutor)', () => {
      it('should return empty properties when no JXAExecutor is provided', async () => {
        const executorWithoutJxa = new QueryExecutor(referenceStore);
        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'message',
          index: 0,
          container: 'application'
        };
        const ref = await executorWithoutJxa.queryObject('Mail', specifier);

        const properties = await executorWithoutJxa.getProperties(ref.id);

        expect(properties).toEqual({});
      });

      it('should return empty elements when no JXAExecutor is provided', async () => {
        const executorWithoutJxa = new QueryExecutor(referenceStore);
        const mailboxSpec: NamedSpecifier = {
          type: 'named',
          element: 'mailbox',
          name: 'INBOX',
          container: 'application'
        };

        const result = await executorWithoutJxa.getElements(mailboxSpec, 'message', 'Mail', 10);

        expect(result.elements).toEqual([]);
        expect(result.count).toBe(0);
        expect(result.hasMore).toBe(false);
      });

      it('should still validate references when no JXAExecutor', async () => {
        const executorWithoutJxa = new QueryExecutor(referenceStore);

        const error = await executorWithoutJxa.getProperties('invalid-ref').catch(e => e);

        expect(error.message).toContain('Reference not found: invalid-ref');
      });
    });

    describe('JXA script generation correctness', () => {
      it('should generate correct JXA for nested specifiers', async () => {
        let capturedScript = '';
        const mockExecutor = {
          execute: async (script: string) => {
            capturedScript = script;
            return {
              exitCode: 0,
              stdout: JSON.stringify({ subject: 'Nested Test' }),
              stderr: ''
            };
          }
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const mailboxSpec: NamedSpecifier = {
          type: 'named',
          element: 'mailbox',
          name: 'INBOX',
          container: 'application'
        };
        const messageSpec: ElementSpecifier = {
          type: 'element',
          element: 'message',
          index: 0,
          container: mailboxSpec
        };
        const ref = await executorWithJxa.queryObject('Mail', messageSpec);

        await executorWithJxa.getProperties(ref.id);

        // Verify nested path in JXA
        expect(capturedScript).toContain('mailboxes.byName("INBOX")');
        expect(capturedScript).toContain('messages[0]');
      });

      it('should generate correct JXA for deeply nested specifiers', async () => {
        let capturedScript = '';
        const mockExecutor = {
          execute: async (script: string) => {
            capturedScript = script;
            return {
              exitCode: 0,
              stdout: JSON.stringify({ name: 'Test Account' }),
              stderr: ''
            };
          }
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const accountSpec: NamedSpecifier = {
          type: 'named',
          element: 'account',
          name: 'Work',
          container: 'application'
        };
        const mailboxSpec: NamedSpecifier = {
          type: 'named',
          element: 'mailbox',
          name: 'INBOX',
          container: accountSpec
        };
        const messageSpec: ElementSpecifier = {
          type: 'element',
          element: 'message',
          index: 5,
          container: mailboxSpec
        };
        const ref = await executorWithJxa.queryObject('Mail', messageSpec);

        await executorWithJxa.getProperties(ref.id);

        // Verify full nested path
        expect(capturedScript).toContain('accounts.byName("Work")');
        expect(capturedScript).toContain('mailboxes.byName("INBOX")');
        expect(capturedScript).toContain('messages[5]');
      });

      it('should escape special characters in names', async () => {
        let capturedScript = '';
        const mockExecutor = {
          execute: async (script: string) => {
            capturedScript = script;
            return {
              exitCode: 0,
              stdout: JSON.stringify({}),
              stderr: ''
            };
          }
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const specifier: NamedSpecifier = {
          type: 'named',
          element: 'mailbox',
          name: 'Test-Folder_123',
          container: 'application'
        };
        const ref = await executorWithJxa.queryObject('Mail', specifier);

        await executorWithJxa.getProperties(ref.id);

        // Verify name is escaped properly
        expect(capturedScript).toContain('byName("Test-Folder_123")');
      });

      it('should handle camelCase conversion for multi-word properties', async () => {
        let capturedScript = '';
        const mockExecutor = {
          execute: async (script: string) => {
            capturedScript = script;
            return {
              exitCode: 0,
              stdout: JSON.stringify({ readStatus: true }),
              stderr: ''
            };
          }
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'message',
          index: 0,
          container: 'application'
        };
        const ref = await executorWithJxa.queryObject('Mail', specifier);

        await executorWithJxa.getProperties(ref.id, ['read status']);

        // Verify camelCase conversion
        expect(capturedScript).toContain('readStatus()');
      });

      it('should lowercase all-uppercase SDEF property names (Cocoa convention)', async () => {
        let capturedScript = '';
        const mockExecutor = {
          execute: async (script: string) => {
            capturedScript = script;
            return {
              exitCode: 0,
              stdout: JSON.stringify({ url: 'https://example.com' }),
              stderr: ''
            };
          }
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'tab',
          index: 0,
          container: 'application'
        };
        const ref = await executorWithJxa.queryObject('Safari', specifier);

        await executorWithJxa.getProperties(ref.id, ['URL']);

        // JXA convention: all-uppercase names become all-lowercase
        expect(capturedScript).toContain('url()');
        expect(capturedScript).not.toContain('URL()');
      });

      it('should handle leading uppercase run with trailing lowercase (URLString → urlString)', async () => {
        let capturedScript = '';
        const mockExecutor = {
          execute: async (script: string) => {
            capturedScript = script;
            return {
              exitCode: 0,
              stdout: JSON.stringify({ urlString: 'test' }),
              stderr: ''
            };
          }
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'tab',
          index: 0,
          container: 'application'
        };
        const ref = await executorWithJxa.queryObject('Safari', specifier);

        await executorWithJxa.getProperties(ref.id, ['URLString']);

        // Cocoa convention: leading uppercase run lowered, last uppercase kept if followed by lowercase
        expect(capturedScript).toContain('urlString()');
      });
    });

    describe('Security: Property name injection prevention', () => {
      it('should reject property names with invalid characters (injection attempt)', async () => {
        const mockExecutor = {
          execute: async () => ({
            exitCode: 0,
            stdout: JSON.stringify({}),
            stderr: ''
          })
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'message',
          index: 0,
          container: 'application'
        };
        const ref = await executorWithJxa.queryObject('Mail', specifier);

        // Attempt injection via property name
        const error = await executorWithJxa.getProperties(ref.id, ['foo; malicious code']).catch(e => e);

        expect(error.message).toContain('invalid characters');
      });

      it('should reject property names with newlines', async () => {
        const mockExecutor = {
          execute: async () => ({
            exitCode: 0,
            stdout: JSON.stringify({}),
            stderr: ''
          })
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'message',
          index: 0,
          container: 'application'
        };
        const ref = await executorWithJxa.queryObject('Mail', specifier);

        // Attempt injection via newline
        const error = await executorWithJxa.getProperties(ref.id, ['foo\nmalicious']).catch(e => e);

        expect(error.message).toContain('invalid characters');
      });

      it('should reject property names exceeding max length', async () => {
        const mockExecutor = {
          execute: async () => ({
            exitCode: 0,
            stdout: JSON.stringify({}),
            stderr: ''
          })
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'message',
          index: 0,
          container: 'application'
        };
        const ref = await executorWithJxa.queryObject('Mail', specifier);

        // Very long property name (DoS attempt)
        const longProp = 'a'.repeat(300);
        const error = await executorWithJxa.getProperties(ref.id, [longProp]).catch(e => e);

        expect(error.message).toContain('exceeds maximum length');
      });

      it('should accept valid property names with spaces, hyphens, and underscores', async () => {
        let capturedScript = '';
        const mockExecutor = {
          execute: async (script: string) => {
            capturedScript = script;
            return {
              exitCode: 0,
              stdout: JSON.stringify({ readStatus: true }),
              stderr: ''
            };
          }
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'message',
          index: 0,
          container: 'application'
        };
        const ref = await executorWithJxa.queryObject('Mail', specifier);

        // Valid property names should work
        await executorWithJxa.getProperties(ref.id, ['read-status', 'message count', 'user_id']);

        // camelCase converts spaces to camelCase, lowercases leading uppercase runs, preserves hyphens and underscores
        expect(capturedScript).toContain('read-status()');
        expect(capturedScript).toContain('messageCount()');
        expect(capturedScript).toContain('user_id()');
      });
    });

    describe('Limit parameter validation', () => {
      it('should reject negative limit', async () => {
        const executorWithJxa = new QueryExecutor(referenceStore);
        const mailboxSpec: NamedSpecifier = {
          type: 'named',
          element: 'mailbox',
          name: 'INBOX',
          container: 'application'
        };

        const error = await executorWithJxa.getElements(mailboxSpec, 'message', 'Mail', -1).catch(e => e);

        expect(error.message).toContain('Invalid limit');
      });

      it('should reject limit exceeding maximum (10000)', async () => {
        const executorWithJxa = new QueryExecutor(referenceStore);
        const mailboxSpec: NamedSpecifier = {
          type: 'named',
          element: 'mailbox',
          name: 'INBOX',
          container: 'application'
        };

        const error = await executorWithJxa.getElements(mailboxSpec, 'message', 'Mail', 10001).catch(e => e);

        expect(error.message).toContain('Invalid limit');
      });

      it('should reject non-integer limit', async () => {
        const executorWithJxa = new QueryExecutor(referenceStore);
        const mailboxSpec: NamedSpecifier = {
          type: 'named',
          element: 'mailbox',
          name: 'INBOX',
          container: 'application'
        };

        const error = await executorWithJxa.getElements(mailboxSpec, 'message', 'Mail', 10.5).catch(e => e);

        expect(error.message).toContain('Invalid limit');
      });

      it('should accept limit of 0', async () => {
        const executorWithJxa = new QueryExecutor(referenceStore);
        const mailboxSpec: NamedSpecifier = {
          type: 'named',
          element: 'mailbox',
          name: 'INBOX',
          container: 'application'
        };

        // With no JXAExecutor, should return empty result
        const result = await executorWithJxa.getElements(mailboxSpec, 'message', 'Mail', 0);

        expect(result.elements).toEqual([]);
        expect(result.count).toBe(0);
      });

      it('should accept limit of 10000 (maximum)', async () => {
        const mockExecutor = {
          execute: async () => ({
            exitCode: 0,
            stdout: JSON.stringify({ count: 0, items: [] }),
            stderr: ''
          })
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const mailboxSpec: NamedSpecifier = {
          type: 'named',
          element: 'mailbox',
          name: 'INBOX',
          container: 'application'
        };

        const result = await executorWithJxa.getElements(mailboxSpec, 'message', 'Mail', 10000);

        expect(result).toBeDefined();
      });
    });

    describe('Empty properties array handling', () => {
      it('should treat empty properties array as request for all properties', async () => {
        let capturedScript = '';
        const mockExecutor = {
          execute: async (script: string) => {
            capturedScript = script;
            return {
              exitCode: 0,
              stdout: JSON.stringify({ subject: 'Test', sender: 'test@test.com' }),
              stderr: ''
            };
          }
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'message',
          index: 0,
          container: 'application'
        };
        const ref = await executorWithJxa.queryObject('Mail', specifier);

        // Empty array should get all properties (same as undefined)
        await executorWithJxa.getProperties(ref.id, []);

        // Should call properties() for all properties
        expect(capturedScript).toContain('properties()');
      });
    });

    describe('Reference list serialization (Fix 1)', () => {
      it('should convert reference_list marker to stored reference IDs', async () => {
        const mockExecutor = {
          execute: async () => ({
            exitCode: 0,
            stdout: JSON.stringify({
              selectedMessages: {
                _type: 'reference_list',
                property: 'selectedMessages',
                count: 3,
                items: [{ index: 0 }, { index: 1 }, { index: 2 }]
              }
            }),
            stderr: ''
          })
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const viewerSpec: ElementSpecifier = {
          type: 'element',
          element: 'message viewer',
          index: 0,
          container: 'application'
        };
        const ref = await executorWithJxa.queryObject('Mail', viewerSpec);

        const properties = await executorWithJxa.getProperties(ref.id, ['selectedMessages']);

        // Should return array of reference IDs, not the raw marker
        expect(Array.isArray(properties.selectedMessages)).toBe(true);
        expect(properties.selectedMessages.length).toBe(3);
        properties.selectedMessages.forEach((refId: string) => {
          expect(refId).toMatch(/^ref_/);
          const storedRef = referenceStore.get(refId);
          expect(storedRef).toBeDefined();
          expect(storedRef!.app).toBe('Mail');
          expect(storedRef!.type).toBe('message');
        });
      });

      it('should generate JXA that detects object arrays for specific properties', async () => {
        let capturedScript = '';
        const mockExecutor = {
          execute: async (script: string) => {
            capturedScript = script;
            return {
              exitCode: 0,
              stdout: JSON.stringify({ selectedMessages: [] }),
              stderr: ''
            };
          }
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const viewerSpec: ElementSpecifier = {
          type: 'element',
          element: 'message viewer',
          index: 0,
          container: 'application'
        };
        const ref = await executorWithJxa.queryObject('Mail', viewerSpec);

        await executorWithJxa.getProperties(ref.id, ['selectedMessages']);

        // JXA should contain the array detection logic checking all elements
        expect(capturedScript).toContain('Array.isArray(val)');
        expect(capturedScript).toContain('val.every');
        expect(capturedScript).toContain('reference_list');
        expect(capturedScript).toContain('selectedMessages');
      });

      it('should pass through plain values without converting to reference_list', async () => {
        const mockExecutor = {
          execute: async () => ({
            exitCode: 0,
            stdout: JSON.stringify({ subject: 'Hello', read: true }),
            stderr: ''
          })
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'message',
          index: 0,
          container: 'application'
        };
        const ref = await executorWithJxa.queryObject('Mail', specifier);

        const properties = await executorWithJxa.getProperties(ref.id, ['subject', 'read']);

        expect(properties.subject).toBe('Hello');
        expect(properties.read).toBe(true);
      });

      it('should skip malformed reference_list markers with missing property', async () => {
        const mockExecutor = {
          execute: async () => ({
            exitCode: 0,
            stdout: JSON.stringify({
              badMarker: {
                _type: 'reference_list',
                // missing 'property' field
                count: 2,
                items: [{ index: 0 }, { index: 1 }]
              }
            }),
            stderr: ''
          })
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'message viewer',
          index: 0,
          container: 'application'
        };
        const ref = await executorWithJxa.queryObject('Mail', specifier);

        const properties = await executorWithJxa.getProperties(ref.id, ['badMarker']);

        // Should pass through the raw marker without converting
        expect(properties.badMarker._type).toBe('reference_list');
        expect(properties.badMarker.count).toBe(2);
      });

      it('should skip malformed reference_list markers with invalid count', async () => {
        const mockExecutor = {
          execute: async () => ({
            exitCode: 0,
            stdout: JSON.stringify({
              badMarker: {
                _type: 'reference_list',
                property: 'selectedMessages',
                count: -1,
                items: []
              }
            }),
            stderr: ''
          })
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'message viewer',
          index: 0,
          container: 'application'
        };
        const ref = await executorWithJxa.queryObject('Mail', specifier);

        const properties = await executorWithJxa.getProperties(ref.id, ['badMarker']);

        // Should pass through — negative count is invalid
        expect(properties.badMarker._type).toBe('reference_list');
      });

      it('should skip malformed reference_list markers with non-integer count', async () => {
        const mockExecutor = {
          execute: async () => ({
            exitCode: 0,
            stdout: JSON.stringify({
              badMarker: {
                _type: 'reference_list',
                property: 'selectedMessages',
                count: 2.5,
                items: []
              }
            }),
            stderr: ''
          })
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'message viewer',
          index: 0,
          container: 'application'
        };
        const ref = await executorWithJxa.queryObject('Mail', specifier);

        const properties = await executorWithJxa.getProperties(ref.id, ['badMarker']);

        // Should pass through — non-integer count is invalid
        expect(properties.badMarker._type).toBe('reference_list');
      });

      it('should use escapeJxaString for defense-in-depth on property names in JXA template', async () => {
        let capturedScript = '';
        const mockExecutor = {
          execute: async (script: string) => {
            capturedScript = script;
            return {
              exitCode: 0,
              stdout: JSON.stringify({ selectedMessages: [] }),
              stderr: ''
            };
          }
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'message viewer',
          index: 0,
          container: 'application'
        };
        const ref = await executorWithJxa.queryObject('Mail', specifier);

        // Valid property name that goes through both sanitize and escape
        await executorWithJxa.getProperties(ref.id, ['selectedMessages']);

        // The JXA template should use the property name consistently
        // (escaped via escapeJxaString for defense-in-depth)
        expect(capturedScript).toContain('selectedMessages');
        // Verify the template wraps property access with array detection
        expect(capturedScript).toContain('val.every');
      });

      it('should handle mixed plain values and reference lists', async () => {
        const mockExecutor = {
          execute: async () => ({
            exitCode: 0,
            stdout: JSON.stringify({
              name: 'Inbox',
              selectedMessages: {
                _type: 'reference_list',
                property: 'selectedMessages',
                count: 2,
                items: [{ index: 0 }, { index: 1 }]
              }
            }),
            stderr: ''
          })
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const viewerSpec: ElementSpecifier = {
          type: 'element',
          element: 'message viewer',
          index: 0,
          container: 'application'
        };
        const ref = await executorWithJxa.queryObject('Mail', viewerSpec);

        const properties = await executorWithJxa.getProperties(ref.id, ['name', 'selectedMessages']);

        expect(properties.name).toBe('Inbox');
        expect(Array.isArray(properties.selectedMessages)).toBe(true);
        expect(properties.selectedMessages.length).toBe(2);
      });
    });

    describe('Specifier chaining through PropertySpecifier (Fix 2)', () => {
      it('should generate direct index when container is PropertySpecifier', async () => {
        let capturedScript = '';
        const mockExecutor = {
          execute: async (script: string) => {
            capturedScript = script;
            return {
              exitCode: 0,
              stdout: JSON.stringify({ subject: 'Test Message' }),
              stderr: ''
            };
          }
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);

        // Create a message viewer reference
        const viewerSpec: ElementSpecifier = {
          type: 'element',
          element: 'message viewer',
          index: 0,
          container: 'application'
        };
        const viewerRef = await executorWithJxa.queryObject('Mail', viewerSpec);

        // Simulate what createPropertyListReferences produces:
        // ElementSpecifier with PropertySpecifier as container
        const propertySpec: PropertySpecifier = {
          type: 'property',
          property: 'selectedMessages',
          of: viewerSpec
        };
        const elementInProperty: ElementSpecifier = {
          type: 'element',
          element: 'message',
          index: 0,
          container: propertySpec
        };
        const msgRef = await executorWithJxa.queryObject('Mail', elementInProperty);

        await executorWithJxa.getProperties(msgRef.id, ['subject']);

        // Should generate: selectedMessages()[0] NOT selectedMessages().messages[0]
        expect(capturedScript).toContain('selectedMessages()');
        expect(capturedScript).toContain('[0]');
        expect(capturedScript).not.toContain('selectedMessages().messages[0]');
      });

      it('should still use element collection for non-property containers', async () => {
        let capturedScript = '';
        const mockExecutor = {
          execute: async (script: string) => {
            capturedScript = script;
            return {
              exitCode: 0,
              stdout: JSON.stringify({ subject: 'Test' }),
              stderr: ''
            };
          }
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const mailboxSpec: NamedSpecifier = {
          type: 'named',
          element: 'mailbox',
          name: 'INBOX',
          container: 'application'
        };
        const messageSpec: ElementSpecifier = {
          type: 'element',
          element: 'message',
          index: 0,
          container: mailboxSpec
        };
        const ref = await executorWithJxa.queryObject('Mail', messageSpec);

        await executorWithJxa.getProperties(ref.id, ['subject']);

        // Should still use element collection: mailboxes.byName("INBOX").messages[0]
        expect(capturedScript).toContain('.messages[0]');
      });
    });

    describe('createPropertyListReferences()', () => {
      it('should create references with correct specifier chain', () => {
        const mockExecutor = {
          execute: async () => ({
            exitCode: 0,
            stdout: '{}',
            stderr: ''
          })
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const viewerSpec: ElementSpecifier = {
          type: 'element',
          element: 'message viewer',
          index: 0,
          container: 'application'
        };

        const refIds = executorWithJxa.createPropertyListReferences(
          'Mail',
          viewerSpec,
          'selectedMessages',
          3
        );

        expect(refIds.length).toBe(3);
        refIds.forEach((refId, index) => {
          const ref = referenceStore.get(refId);
          expect(ref).toBeDefined();
          expect(ref!.app).toBe('Mail');
          expect(ref!.type).toBe('message'); // singularized from selectedMessages

          // Verify specifier structure
          const spec = ref!.specifier as ElementSpecifier;
          expect(spec.type).toBe('element');
          expect(spec.element).toBe('message');
          expect(spec.index).toBe(index);

          // Container should be a PropertySpecifier
          const container = spec.container as PropertySpecifier;
          expect(container.type).toBe('property');
          expect(container.property).toBe('selectedMessages');
          expect(container.of).toEqual(viewerSpec);
        });
      });

      it('should singularize property names correctly', () => {
        const mockExecutor = {
          execute: async () => ({
            exitCode: 0,
            stdout: '{}',
            stderr: ''
          })
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const appSpec = { type: 'application' as const };

        // "selectedMessages" → "message"
        const refs1 = executorWithJxa.createPropertyListReferences('Mail', appSpec, 'selectedMessages', 1);
        expect(referenceStore.get(refs1[0])!.type).toBe('message');

        // "windows" → "window"
        const refs2 = executorWithJxa.createPropertyListReferences('Finder', appSpec, 'windows', 1);
        expect(referenceStore.get(refs2[0])!.type).toBe('window');

        // "visibleDocuments" → "document"
        const refs3 = executorWithJxa.createPropertyListReferences('TextEdit', appSpec, 'visibleDocuments', 1);
        expect(referenceStore.get(refs3[0])!.type).toBe('document');
      });

      it('should handle zero-count property list', () => {
        const mockExecutor = {
          execute: async () => ({
            exitCode: 0,
            stdout: '{}',
            stderr: ''
          })
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const appSpec = { type: 'application' as const };

        const refIds = executorWithJxa.createPropertyListReferences('Mail', appSpec, 'selectedMessages', 0);

        expect(refIds).toEqual([]);
      });
    });

    describe('Object reference serialization (single objects)', () => {
      it('should convert object_reference marker to stored reference ID', async () => {
        const mockExecutor = {
          execute: async () => ({
            exitCode: 0,
            stdout: JSON.stringify({
              mailbox: { _type: 'object_reference', property: 'mailbox' }
            }),
            stderr: ''
          })
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'message',
          index: 0,
          container: 'application'
        };
        const ref = await executorWithJxa.queryObject('Mail', specifier);

        const properties = await executorWithJxa.getProperties(ref.id, ['mailbox']);

        // Should return a reference ID string, not the raw marker
        expect(typeof properties.mailbox).toBe('string');
        expect(properties.mailbox).toMatch(/^ref_/);
        const storedRef = referenceStore.get(properties.mailbox);
        expect(storedRef).toBeDefined();
        expect(storedRef!.app).toBe('Mail');
        expect(storedRef!.type).toBe('mailbox');
        // Should be a PropertySpecifier
        expect(storedRef!.specifier.type).toBe('property');
        expect((storedRef!.specifier as PropertySpecifier).property).toBe('mailbox');
      });

      it('should generate JXA that detects single objects for specific properties', async () => {
        let capturedScript = '';
        const mockExecutor = {
          execute: async (script: string) => {
            capturedScript = script;
            return {
              exitCode: 0,
              stdout: JSON.stringify({ mailbox: 'test' }),
              stderr: ''
            };
          }
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'message',
          index: 0,
          container: 'application'
        };
        const ref = await executorWithJxa.queryObject('Mail', specifier);

        await executorWithJxa.getProperties(ref.id, ['mailbox']);

        // Verify JXA contains the single-object detection logic (uses isObj helper)
        expect(capturedScript).toContain('!Array.isArray(val) && isObj(val)');
        expect(capturedScript).toContain('object_reference');
      });

      it('should handle mixed plain values, reference lists, and object references', async () => {
        const mockExecutor = {
          execute: async () => ({
            exitCode: 0,
            stdout: JSON.stringify({
              name: 'Test Message',
              selectedMessages: {
                _type: 'reference_list',
                property: 'selectedMessages',
                count: 2,
                items: [{ index: 0 }, { index: 1 }]
              },
              mailbox: { _type: 'object_reference', property: 'mailbox' }
            }),
            stderr: ''
          })
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'message viewer',
          index: 0,
          container: 'application'
        };
        const ref = await executorWithJxa.queryObject('Mail', specifier);

        const properties = await executorWithJxa.getProperties(ref.id, ['name', 'selectedMessages', 'mailbox']);

        // Plain value
        expect(properties.name).toBe('Test Message');
        // Reference list
        expect(Array.isArray(properties.selectedMessages)).toBe(true);
        expect(properties.selectedMessages.length).toBe(2);
        properties.selectedMessages.forEach((refId: string) => {
          expect(refId).toMatch(/^ref_/);
        });
        // Object reference
        expect(typeof properties.mailbox).toBe('string');
        expect(properties.mailbox).toMatch(/^ref_/);
        const mailboxRef = referenceStore.get(properties.mailbox);
        expect(mailboxRef).toBeDefined();
        expect(mailboxRef!.type).toBe('mailbox');
      });

      it('should handle object_reference in all-properties path', async () => {
        const mockExecutor = {
          execute: async () => ({
            exitCode: 0,
            stdout: JSON.stringify({
              name: 'INBOX',
              mailbox: { _type: 'object_reference', property: 'mailbox' }
            }),
            stderr: ''
          })
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'message',
          index: 0,
          container: 'application'
        };
        const ref = await executorWithJxa.queryObject('Mail', specifier);

        // Call without specific properties (all-properties path)
        const properties = await executorWithJxa.getProperties(ref.id);

        expect(properties.name).toBe('INBOX');
        // object_reference should be converted to a stored reference
        expect(typeof properties.mailbox).toBe('string');
        expect(properties.mailbox).toMatch(/^ref_/);
        const storedRef = referenceStore.get(properties.mailbox);
        expect(storedRef).toBeDefined();
        expect(storedRef!.type).toBe('mailbox');
      });

      it('should skip malformed object_reference markers with missing property', async () => {
        const mockExecutor = {
          execute: async () => ({
            exitCode: 0,
            stdout: JSON.stringify({
              badMarker: { _type: 'object_reference' }
            }),
            stderr: ''
          })
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'message',
          index: 0,
          container: 'application'
        };
        const ref = await executorWithJxa.queryObject('Mail', specifier);

        const properties = await executorWithJxa.getProperties(ref.id, ['badMarker']);

        // Should pass through unchanged (no property field to create reference from)
        expect(properties.badMarker._type).toBe('object_reference');
        expect(properties.badMarker.property).toBeUndefined();
      });

      it('should detect object_reference when JSON.stringify returns undefined (JXA host objects)', async () => {
        let capturedScript = '';
        const mockExecutor = {
          execute: async (script: string) => {
            capturedScript = script;
            return {
              exitCode: 0,
              stdout: JSON.stringify({
                currentTab: { _type: 'object_reference', property: 'currentTab' }
              }),
              stderr: ''
            };
          }
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'window',
          index: 0,
          container: 'application'
        };
        const ref = await executorWithJxa.queryObject('Safari', specifier);

        const properties = await executorWithJxa.getProperties(ref.id, ['currentTab']);

        // Verify JXA template checks for undefined from JSON.stringify
        // (JSON.stringify returns undefined for JXA host objects like tabs)
        expect(capturedScript).toContain('str === undefined');

        // Post-processing should convert to stored reference
        expect(typeof properties.currentTab).toBe('string');
        expect(properties.currentTab).toMatch(/^ref_/);
        const storedRef = referenceStore.get(properties.currentTab);
        expect(storedRef).toBeDefined();
        expect(storedRef!.type).toBe('tab');
      });

      it('should detect JXA object specifiers with typeof function (not just object)', async () => {
        let capturedScript = '';
        const mockExecutor = {
          execute: async (script: string) => {
            capturedScript = script;
            return {
              exitCode: 0,
              stdout: JSON.stringify({
                currentTab: { _type: 'object_reference', property: 'currentTab' },
                selectedMessages: { _type: 'reference_list', property: 'selectedMessages', count: 1, items: [{ index: 0 }] }
              }),
              stderr: ''
            };
          }
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'window',
          index: 0,
          container: 'application'
        };
        const ref = await executorWithJxa.queryObject('Safari', specifier);

        await executorWithJxa.getProperties(ref.id, ['currentTab', 'selectedMessages']);

        // JXA object specifiers report typeof === 'function', so detection must check for both
        expect(capturedScript).toContain("typeof v === 'function'");
      });
    });

    describe('Per-property error resilience (_error markers)', () => {
      it('should return _error for properties that throw', async () => {
        const mockExecutor = {
          execute: async () => ({
            exitCode: 0,
            stdout: JSON.stringify({
              name: 'Tab 1',
              url: { _error: 'property access failed' }
            }),
            stderr: ''
          })
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'tab',
          index: 0,
          container: 'application'
        };
        const ref = await executorWithJxa.queryObject('Safari', specifier);

        const properties = await executorWithJxa.getProperties(ref.id, ['name', 'url']);

        expect(properties.name).toBe('Tab 1');
        expect(properties.url).toEqual({ _error: 'property access failed' });
      });

      it('should generate JXA with try-catch around each property IIFE', async () => {
        let capturedScript = '';
        const mockExecutor = {
          execute: async (script: string) => {
            capturedScript = script;
            return {
              exitCode: 0,
              stdout: JSON.stringify({ name: 'test' }),
              stderr: ''
            };
          }
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'tab',
          index: 0,
          container: 'application'
        };
        const ref = await executorWithJxa.queryObject('Safari', specifier);

        await executorWithJxa.getProperties(ref.id, ['name']);

        expect(capturedScript).toContain('catch(e)');
        expect(capturedScript).toContain('_error');
      });

      it('should pass through _error markers without post-processing', async () => {
        const mockExecutor = {
          execute: async () => ({
            exitCode: 0,
            stdout: JSON.stringify({
              url: { _error: 'Cannot access property' }
            }),
            stderr: ''
          })
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'tab',
          index: 0,
          container: 'application'
        };
        const ref = await executorWithJxa.queryObject('Safari', specifier);

        const properties = await executorWithJxa.getProperties(ref.id, ['url']);

        // _error objects don't have _type field, so they should not be converted to references
        expect(properties.url._error).toBe('Cannot access property');
        expect(properties.url._type).toBeUndefined();
      });

      it('should handle all properties failing with _error', async () => {
        const mockExecutor = {
          execute: async () => ({
            exitCode: 0,
            stdout: JSON.stringify({
              name: { _error: 'property access failed' },
              url: { _error: 'property access failed' },
              title: { _error: 'not available' }
            }),
            stderr: ''
          })
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'tab',
          index: 0,
          container: 'application'
        };
        const ref = await executorWithJxa.queryObject('Safari', specifier);

        const properties = await executorWithJxa.getProperties(ref.id, ['name', 'url', 'title']);

        expect(properties.name).toEqual({ _error: 'property access failed' });
        expect(properties.url).toEqual({ _error: 'property access failed' });
        expect(properties.title).toEqual({ _error: 'not available' });
      });

      it('should attempt String() coercion before returning _error', async () => {
        let capturedScript = '';
        const mockExecutor = {
          execute: async (script: string) => {
            capturedScript = script;
            return {
              exitCode: 0,
              stdout: JSON.stringify({
                url: 'https://example.com'
              }),
              stderr: ''
            };
          }
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'tab',
          index: 0,
          container: 'application'
        };
        const ref = await executorWithJxa.queryObject('Safari', specifier);

        const properties = await executorWithJxa.getProperties(ref.id, ['url']);

        // The outer catch should try String() coercion before falling back to _error
        // This handles NSURL and other JXA types that throw on direct access
        // but can be coerced to string
        expect(capturedScript).toContain('String(');

        // Verify end-to-end: when String() coercion succeeds, the value comes through
        expect(properties.url).toBe('https://example.com');
      });

      it('should include coercion failure info in _error when String() also fails', async () => {
        let capturedScript = '';
        const mockExecutor = {
          execute: async (script: string) => {
            capturedScript = script;
            return {
              exitCode: 0,
              stdout: JSON.stringify({
                url: { _error: "Can't convert types. (String coercion also failed)" }
              }),
              stderr: ''
            };
          }
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'tab',
          index: 0,
          container: 'application'
        };
        const ref = await executorWithJxa.queryObject('Safari', specifier);

        const properties = await executorWithJxa.getProperties(ref.id, ['url']);

        // Verify the enriched error message includes coercion failure info
        expect(capturedScript).toContain('String coercion also failed');
        expect(properties.url._error).toContain('String coercion also failed');
      });
    });

    describe('createPropertyReference()', () => {
      it('should create reference with PropertySpecifier', () => {
        const mockExecutor = {
          execute: async () => ({
            exitCode: 0,
            stdout: '{}',
            stderr: ''
          })
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const parentSpec: ElementSpecifier = {
          type: 'element',
          element: 'message',
          index: 0,
          container: 'application'
        };

        const refId = executorWithJxa.createPropertyReference('Mail', parentSpec, 'mailbox');

        expect(refId).toMatch(/^ref_/);
        const storedRef = referenceStore.get(refId);
        expect(storedRef).toBeDefined();
        expect(storedRef!.app).toBe('Mail');
        expect(storedRef!.type).toBe('mailbox');
        // Should be a PropertySpecifier
        expect(storedRef!.specifier.type).toBe('property');
        const propSpec = storedRef!.specifier as PropertySpecifier;
        expect(propSpec.property).toBe('mailbox');
        expect(propSpec.of).toEqual(parentSpec);
      });

      it('should singularize property names for type', () => {
        const mockExecutor = {
          execute: async () => ({
            exitCode: 0,
            stdout: '{}',
            stderr: ''
          })
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const parentSpec: ElementSpecifier = {
          type: 'element',
          element: 'window',
          index: 0,
          container: 'application'
        };

        const refId = executorWithJxa.createPropertyReference('Safari', parentSpec, 'currentTab');

        const storedRef = referenceStore.get(refId);
        expect(storedRef).toBeDefined();
        // 'currentTab' -> strip 'current' prefix -> 'tab'
        expect(storedRef!.type).toBe('tab');
      });

      it('should handle property names without prefix', () => {
        const mockExecutor = {
          execute: async () => ({
            exitCode: 0,
            stdout: '{}',
            stderr: ''
          })
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const parentSpec: ElementSpecifier = {
          type: 'element',
          element: 'message',
          index: 0,
          container: 'application'
        };

        const refId = executorWithJxa.createPropertyReference('Mail', parentSpec, 'mailbox');

        const storedRef = referenceStore.get(refId);
        expect(storedRef).toBeDefined();
        // 'mailbox' has no known prefix, stays as 'mailbox'
        expect(storedRef!.type).toBe('mailbox');
      });
    });

    describe('getElementsWithProperties() batch operation', () => {
      it('should fetch elements with properties in single JXA call', async () => {
        const mockExecutor = {
          execute: async () => ({
            exitCode: 0,
            stdout: JSON.stringify({
              count: 2,
              items: [
                { index: 0, props: { subject: 'Hello', sender: 'alice@test.com' } },
                { index: 1, props: { subject: 'World', sender: 'bob@test.com' } }
              ]
            }),
            stderr: ''
          })
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const mailboxSpec: NamedSpecifier = {
          type: 'named',
          element: 'mailbox',
          name: 'INBOX',
          container: 'application'
        };
        const ref = await executorWithJxa.queryObject('Mail', mailboxSpec);

        const result = await executorWithJxa.getElementsWithProperties(
          ref.id, 'message', ['subject', 'sender'], undefined, 10
        );

        expect(result.count).toBe(2);
        expect(result.elements.length).toBe(2);
        expect(result.hasMore).toBe(false);
        // Verify references created
        result.elements.forEach((el, index) => {
          expect(el.reference.id).toMatch(/^ref_/);
          expect(el.reference.app).toBe('Mail');
          expect(el.reference.type).toBe('message');
          expect(referenceStore.get(el.reference.id)).toEqual(el.reference);
        });
        // Verify properties
        expect(result.elements[0].properties.subject).toBe('Hello');
        expect(result.elements[0].properties.sender).toBe('alice@test.com');
        expect(result.elements[1].properties.subject).toBe('World');
        expect(result.elements[1].properties.sender).toBe('bob@test.com');
      });

      it('should generate JXA with property accessors for each element', async () => {
        let capturedScript = '';
        const mockExecutor = {
          execute: async (script: string) => {
            capturedScript = script;
            return {
              exitCode: 0,
              stdout: JSON.stringify({ count: 0, items: [] }),
              stderr: ''
            };
          }
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const mailboxSpec: NamedSpecifier = {
          type: 'named',
          element: 'mailbox',
          name: 'INBOX',
          container: 'application'
        };
        const ref = await executorWithJxa.queryObject('Mail', mailboxSpec);

        await executorWithJxa.getElementsWithProperties(
          ref.id, 'message', ['subject', 'sender'], undefined, 10
        );

        // Verify the JXA script contains property access within element iteration
        expect(capturedScript).toContain('subject');
        expect(capturedScript).toContain('sender');
        expect(capturedScript).toContain('el.');
        expect(capturedScript).toContain('props');
      });

      it('should handle per-property errors in batch results', async () => {
        const mockExecutor = {
          execute: async () => ({
            exitCode: 0,
            stdout: JSON.stringify({
              count: 1,
              items: [
                {
                  index: 0,
                  props: {
                    name: 'Tab 1',
                    url: { _error: 'property access failed' }
                  }
                }
              ]
            }),
            stderr: ''
          })
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const specifier: NamedSpecifier = {
          type: 'named',
          element: 'window',
          name: 'Main',
          container: 'application'
        };
        const ref = await executorWithJxa.queryObject('Safari', specifier);

        const result = await executorWithJxa.getElementsWithProperties(
          ref.id, 'tab', ['name', 'url'], undefined, 10
        );

        expect(result.elements[0].properties.name).toBe('Tab 1');
        expect(result.elements[0].properties.url).toEqual({ _error: 'property access failed' });
      });

      it('should convert reference markers in batch properties', async () => {
        const mockExecutor = {
          execute: async () => ({
            exitCode: 0,
            stdout: JSON.stringify({
              count: 1,
              items: [
                {
                  index: 0,
                  props: {
                    name: 'Message 1',
                    attachments: {
                      _type: 'reference_list',
                      property: 'attachments',
                      count: 2,
                      items: [{ index: 0 }, { index: 1 }]
                    },
                    mailbox: { _type: 'object_reference', property: 'mailbox' }
                  }
                }
              ]
            }),
            stderr: ''
          })
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const mailboxSpec: NamedSpecifier = {
          type: 'named',
          element: 'mailbox',
          name: 'INBOX',
          container: 'application'
        };
        const ref = await executorWithJxa.queryObject('Mail', mailboxSpec);

        const result = await executorWithJxa.getElementsWithProperties(
          ref.id, 'message', ['name', 'attachments', 'mailbox'], undefined, 10
        );

        // Plain value
        expect(result.elements[0].properties.name).toBe('Message 1');
        // Reference list should be converted to array of ref IDs
        expect(Array.isArray(result.elements[0].properties.attachments)).toBe(true);
        expect(result.elements[0].properties.attachments.length).toBe(2);
        result.elements[0].properties.attachments.forEach((refId: string) => {
          expect(refId).toMatch(/^ref_/);
        });
        // Object reference should be converted to a single ref ID
        expect(typeof result.elements[0].properties.mailbox).toBe('string');
        expect(result.elements[0].properties.mailbox).toMatch(/^ref_/);
      });

      it('should return empty result when no JXAExecutor', async () => {
        const executorWithoutJxa = new QueryExecutor(referenceStore);
        const mailboxSpec: NamedSpecifier = {
          type: 'named',
          element: 'mailbox',
          name: 'INBOX',
          container: 'application'
        };

        const result = await executorWithoutJxa.getElementsWithProperties(
          mailboxSpec, 'message', ['subject'], 'Mail', 10
        );

        expect(result.elements).toEqual([]);
        expect(result.count).toBe(0);
        expect(result.hasMore).toBe(false);
      });

      it('should require non-empty properties array', async () => {
        const mockExecutor = {
          execute: async () => ({
            exitCode: 0,
            stdout: '{}',
            stderr: ''
          })
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const mailboxSpec: NamedSpecifier = {
          type: 'named',
          element: 'mailbox',
          name: 'INBOX',
          container: 'application'
        };

        const error = await executorWithJxa.getElementsWithProperties(
          mailboxSpec, 'message', [], 'Mail', 10
        ).catch(e => e);

        expect(error.message).toContain('Properties array must not be empty');
      });

      it('should validate limit parameter', async () => {
        const mockExecutor = {
          execute: async () => ({
            exitCode: 0,
            stdout: '{}',
            stderr: ''
          })
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const mailboxSpec: NamedSpecifier = {
          type: 'named',
          element: 'mailbox',
          name: 'INBOX',
          container: 'application'
        };

        // Negative limit
        const error1 = await executorWithJxa.getElementsWithProperties(
          mailboxSpec, 'message', ['subject'], 'Mail', -1
        ).catch(e => e);
        expect(error1.message).toContain('Invalid limit');

        // Exceeds max
        const error2 = await executorWithJxa.getElementsWithProperties(
          mailboxSpec, 'message', ['subject'], 'Mail', 10001
        ).catch(e => e);
        expect(error2.message).toContain('Invalid limit');

        // Non-integer
        const error3 = await executorWithJxa.getElementsWithProperties(
          mailboxSpec, 'message', ['subject'], 'Mail', 5.5
        ).catch(e => e);
        expect(error3.message).toContain('Invalid limit');
      });

      it('should accept reference ID as container', async () => {
        const mockExecutor = {
          execute: async () => ({
            exitCode: 0,
            stdout: JSON.stringify({
              count: 1,
              items: [{ index: 0, props: { subject: 'Test' } }]
            }),
            stderr: ''
          })
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const mailboxSpec: NamedSpecifier = {
          type: 'named',
          element: 'mailbox',
          name: 'INBOX',
          container: 'application'
        };
        const ref = await executorWithJxa.queryObject('Mail', mailboxSpec);

        const result = await executorWithJxa.getElementsWithProperties(
          ref.id, 'message', ['subject'], undefined, 10
        );

        expect(result.elements.length).toBe(1);
        expect(result.elements[0].properties.subject).toBe('Test');
      });

      it('should accept ObjectSpecifier as container with app', async () => {
        const mockExecutor = {
          execute: async () => ({
            exitCode: 0,
            stdout: JSON.stringify({
              count: 1,
              items: [{ index: 0, props: { subject: 'Test' } }]
            }),
            stderr: ''
          })
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);
        const mailboxSpec: NamedSpecifier = {
          type: 'named',
          element: 'mailbox',
          name: 'INBOX',
          container: 'application'
        };

        const result = await executorWithJxa.getElementsWithProperties(
          mailboxSpec, 'message', ['subject'], 'Mail', 10
        );

        expect(result.elements.length).toBe(1);
        expect(result.elements[0].reference.app).toBe('Mail');
      });

      it('should throw on invalid reference container', async () => {
        const mockExecutor = {
          execute: async () => ({
            exitCode: 0,
            stdout: '{}',
            stderr: ''
          })
        };

        const executorWithJxa = new QueryExecutor(referenceStore, mockExecutor as any);

        const error = await executorWithJxa.getElementsWithProperties(
          'ref_nonexistent-id', 'message', ['subject'], undefined, 10
        ).catch(e => e);

        expect(error.message).toContain('Reference not found: ref_nonexistent-id');
      });

      it('should return hasMore correctly', async () => {
        // Test hasMore=true when count > limit
        const mockExecutorMore = {
          execute: async () => ({
            exitCode: 0,
            stdout: JSON.stringify({
              count: 50,
              items: [
                { index: 0, props: { subject: 'Msg 1' } },
                { index: 1, props: { subject: 'Msg 2' } }
              ]
            }),
            stderr: ''
          })
        };

        const executorMore = new QueryExecutor(referenceStore, mockExecutorMore as any);
        const mailboxSpec: NamedSpecifier = {
          type: 'named',
          element: 'mailbox',
          name: 'INBOX',
          container: 'application'
        };
        const ref1 = await executorMore.queryObject('Mail', mailboxSpec);

        const resultMore = await executorMore.getElementsWithProperties(
          ref1.id, 'message', ['subject'], undefined, 2
        );
        expect(resultMore.hasMore).toBe(true);
        expect(resultMore.count).toBe(50);

        // Test hasMore=false when count <= limit
        const mockExecutorNoMore = {
          execute: async () => ({
            exitCode: 0,
            stdout: JSON.stringify({
              count: 2,
              items: [
                { index: 0, props: { subject: 'Msg 1' } },
                { index: 1, props: { subject: 'Msg 2' } }
              ]
            }),
            stderr: ''
          })
        };

        const executorNoMore = new QueryExecutor(referenceStore, mockExecutorNoMore as any);
        const ref2 = await executorNoMore.queryObject('Mail', mailboxSpec);

        const resultNoMore = await executorNoMore.getElementsWithProperties(
          ref2.id, 'message', ['subject'], undefined, 10
        );
        expect(resultNoMore.hasMore).toBe(false);
        expect(resultNoMore.count).toBe(2);
      });
    });
  });
});
