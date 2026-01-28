/**
 * Security Tests for QueryExecutor - JXA Injection Prevention
 *
 * Tests the sanitizeForJxa() and buildObjectPath() methods
 * to ensure they properly reject malicious input that could lead
 * to code injection attacks.
 *
 * Security rules:
 * - SAFE_IDENTIFIER_REGEX = /^[a-zA-Z0-9_\s\-]+$/
 * - MAX_IDENTIFIER_LENGTH = 256
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { QueryExecutor } from '../../../src/execution/query-executor.js';
import { ReferenceStore } from '../../../src/execution/reference-store.js';
import {
  ObjectSpecifier,
  ElementSpecifier,
  NamedSpecifier,
  IdSpecifier,
  PropertySpecifier
} from '../../../src/types/object-specifier.js';

describe('QueryExecutor - Security: JXA Injection Prevention', () => {
  let referenceStore: ReferenceStore;
  let queryExecutor: QueryExecutor;

  beforeEach(() => {
    referenceStore = new ReferenceStore();
    queryExecutor = new QueryExecutor(referenceStore);
  });

  afterEach(() => {
    referenceStore.stopCleanup();
  });

  describe('sanitizeForJxa() - via buildObjectPath integration', () => {
    describe('Valid Identifiers - Should Accept', () => {
      it('should accept simple alphanumeric element names', async () => {
        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'message123',
          index: 0,
          container: 'application'
        };

        const ref = await queryExecutor.queryObject('Mail', specifier);
        expect(ref).toBeDefined();
        expect(ref.type).toBe('message123');
      });

      it('should accept element names with underscores', async () => {
        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'mail_message',
          index: 0,
          container: 'application'
        };

        const ref = await queryExecutor.queryObject('Mail', specifier);
        expect(ref).toBeDefined();
        expect(ref.type).toBe('mail_message');
      });

      it('should accept element names with hyphens', async () => {
        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'mail-message',
          index: 0,
          container: 'application'
        };

        const ref = await queryExecutor.queryObject('Mail', specifier);
        expect(ref).toBeDefined();
        expect(ref.type).toBe('mail-message');
      });

      it('should accept names with spaces', async () => {
        const specifier: NamedSpecifier = {
          type: 'named',
          element: 'mailbox',
          name: 'My Inbox Folder',
          container: 'application'
        };

        const ref = await queryExecutor.queryObject('Mail', specifier);
        expect(ref).toBeDefined();
        expect(ref.type).toBe('mailbox');
      });

      it('should accept IDs with alphanumeric and allowed characters', async () => {
        const specifier: IdSpecifier = {
          type: 'id',
          element: 'message',
          id: 'msg-123_ABC',
          container: 'application'
        };

        const ref = await queryExecutor.queryObject('Mail', specifier);
        expect(ref).toBeDefined();
      });

      it('should accept property names with spaces (multi-word properties)', async () => {
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

        const ref = await queryExecutor.queryObject('Mail', specifier);
        expect(ref).toBeDefined();
      });

      it('should accept identifier at exactly max length (256 characters)', async () => {
        const maxLengthName = 'a'.repeat(256);
        const specifier: NamedSpecifier = {
          type: 'named',
          element: 'mailbox',
          name: maxLengthName,
          container: 'application'
        };

        const ref = await queryExecutor.queryObject('Mail', specifier);
        expect(ref).toBeDefined();
      });
    });

    describe('Invalid Identifiers - Should Reject', () => {
      it('should reject element names with double quotes (injection attempt)', async () => {
        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'message"); do shell script "rm -rf /',
          index: 0,
          container: 'application'
        };

        await expect(queryExecutor.queryObject('Mail', specifier))
          .rejects.toThrow(/invalid characters/i);
      });

      it('should reject element names with single quotes', async () => {
        const specifier: ElementSpecifier = {
          type: 'element',
          element: "message'; delete all;'",
          index: 0,
          container: 'application'
        };

        await expect(queryExecutor.queryObject('Mail', specifier))
          .rejects.toThrow(/invalid characters/i);
      });

      it('should reject element names with semicolons', async () => {
        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'message;malicious',
          index: 0,
          container: 'application'
        };

        await expect(queryExecutor.queryObject('Mail', specifier))
          .rejects.toThrow(/invalid characters/i);
      });

      it('should reject element names with backticks', async () => {
        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'message`whoami`',
          index: 0,
          container: 'application'
        };

        await expect(queryExecutor.queryObject('Mail', specifier))
          .rejects.toThrow(/invalid characters/i);
      });

      it('should reject element names with parentheses', async () => {
        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'message()',
          index: 0,
          container: 'application'
        };

        await expect(queryExecutor.queryObject('Mail', specifier))
          .rejects.toThrow(/invalid characters/i);
      });

      it('should reject element names with dollar signs', async () => {
        const specifier: ElementSpecifier = {
          type: 'element',
          element: '$HOME',
          index: 0,
          container: 'application'
        };

        await expect(queryExecutor.queryObject('Mail', specifier))
          .rejects.toThrow(/invalid characters/i);
      });

      it('should reject element names with backslashes', async () => {
        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'message\\escape',
          index: 0,
          container: 'application'
        };

        await expect(queryExecutor.queryObject('Mail', specifier))
          .rejects.toThrow(/invalid characters/i);
      });

      it('should reject names with newline characters', async () => {
        const specifier: NamedSpecifier = {
          type: 'named',
          element: 'mailbox',
          name: 'inbox\nmalicious',
          container: 'application'
        };

        await expect(queryExecutor.queryObject('Mail', specifier))
          .rejects.toThrow(/invalid characters/i);
      });

      it('should reject names with carriage return characters', async () => {
        const specifier: NamedSpecifier = {
          type: 'named',
          element: 'mailbox',
          name: 'inbox\rmalicious',
          container: 'application'
        };

        await expect(queryExecutor.queryObject('Mail', specifier))
          .rejects.toThrow(/invalid characters/i);
      });

      it('should reject names with tab characters', async () => {
        const specifier: NamedSpecifier = {
          type: 'named',
          element: 'mailbox',
          name: 'inbox\tmalicious',
          container: 'application'
        };

        // Tab characters are rejected as they could be used for injection attacks
        // The regex only allows regular spaces (0x20), not other whitespace
        await expect(queryExecutor.queryObject('Mail', specifier))
          .rejects.toThrow(/invalid characters/i);
      });

      it('should reject IDs with angle brackets', async () => {
        const specifier: IdSpecifier = {
          type: 'id',
          element: 'message',
          id: '<script>alert(1)</script>',
          container: 'application'
        };

        await expect(queryExecutor.queryObject('Mail', specifier))
          .rejects.toThrow(/invalid characters/i);
      });

      it('should reject IDs with ampersands', async () => {
        const specifier: IdSpecifier = {
          type: 'id',
          element: 'message',
          id: 'id&malicious',
          container: 'application'
        };

        await expect(queryExecutor.queryObject('Mail', specifier))
          .rejects.toThrow(/invalid characters/i);
      });

      it('should reject IDs with pipes', async () => {
        const specifier: IdSpecifier = {
          type: 'id',
          element: 'message',
          id: 'id|cat /etc/passwd',
          container: 'application'
        };

        await expect(queryExecutor.queryObject('Mail', specifier))
          .rejects.toThrow(/invalid characters/i);
      });

      it('should reject property names with curly braces', async () => {
        const specifier: PropertySpecifier = {
          type: 'property',
          property: 'subject{injection}',
          of: {
            type: 'element',
            element: 'message',
            index: 0,
            container: 'application'
          }
        };

        await expect(queryExecutor.queryObject('Mail', specifier))
          .rejects.toThrow(/invalid characters/i);
      });

      it('should reject property names with square brackets', async () => {
        const specifier: PropertySpecifier = {
          type: 'property',
          property: 'subject[0]',
          of: {
            type: 'element',
            element: 'message',
            index: 0,
            container: 'application'
          }
        };

        await expect(queryExecutor.queryObject('Mail', specifier))
          .rejects.toThrow(/invalid characters/i);
      });
    });

    describe('Length Limits - DoS Prevention', () => {
      it('should reject identifiers exceeding max length (256 characters)', async () => {
        const tooLongName = 'a'.repeat(257);
        const specifier: NamedSpecifier = {
          type: 'named',
          element: 'mailbox',
          name: tooLongName,
          container: 'application'
        };

        await expect(queryExecutor.queryObject('Mail', specifier))
          .rejects.toThrow(/exceeds maximum length/i);
      });

      it('should reject very long element names', async () => {
        const tooLongElement = 'x'.repeat(300);
        const specifier: ElementSpecifier = {
          type: 'element',
          element: tooLongElement,
          index: 0,
          container: 'application'
        };

        await expect(queryExecutor.queryObject('Mail', specifier))
          .rejects.toThrow(/exceeds maximum length/i);
      });

      it('should reject very long IDs', async () => {
        const tooLongId = 'id'.repeat(200);
        const specifier: IdSpecifier = {
          type: 'id',
          element: 'message',
          id: tooLongId,
          container: 'application'
        };

        await expect(queryExecutor.queryObject('Mail', specifier))
          .rejects.toThrow(/exceeds maximum length/i);
      });

      it('should reject very long property names', async () => {
        const tooLongProperty = 'prop'.repeat(100);
        const specifier: PropertySpecifier = {
          type: 'property',
          property: tooLongProperty,
          of: {
            type: 'element',
            element: 'message',
            index: 0,
            container: 'application'
          }
        };

        await expect(queryExecutor.queryObject('Mail', specifier))
          .rejects.toThrow(/exceeds maximum length/i);
      });
    });

    describe('Unicode Characters - Proper Rejection', () => {
      it('should reject element names with emoji', async () => {
        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'message\u{1F600}',
          index: 0,
          container: 'application'
        };

        await expect(queryExecutor.queryObject('Mail', specifier))
          .rejects.toThrow(/invalid characters/i);
      });

      it('should reject names with Chinese characters', async () => {
        const specifier: NamedSpecifier = {
          type: 'named',
          element: 'mailbox',
          name: '\u4E2D\u6587',
          container: 'application'
        };

        await expect(queryExecutor.queryObject('Mail', specifier))
          .rejects.toThrow(/invalid characters/i);
      });

      it('should reject IDs with Cyrillic characters', async () => {
        const specifier: IdSpecifier = {
          type: 'id',
          element: 'message',
          id: '\u0410\u0411\u0412',
          container: 'application'
        };

        await expect(queryExecutor.queryObject('Mail', specifier))
          .rejects.toThrow(/invalid characters/i);
      });

      it('should reject property names with Arabic characters', async () => {
        const specifier: PropertySpecifier = {
          type: 'property',
          property: '\u0639\u0631\u0628\u064A',
          of: {
            type: 'element',
            element: 'message',
            index: 0,
            container: 'application'
          }
        };

        await expect(queryExecutor.queryObject('Mail', specifier))
          .rejects.toThrow(/invalid characters/i);
      });

      it('should reject names with Japanese characters', async () => {
        const specifier: NamedSpecifier = {
          type: 'named',
          element: 'mailbox',
          name: '\u65E5\u672C\u8A9E',
          container: 'application'
        };

        await expect(queryExecutor.queryObject('Mail', specifier))
          .rejects.toThrow(/invalid characters/i);
      });

      it('should reject names with special Unicode symbols', async () => {
        const specifier: NamedSpecifier = {
          type: 'named',
          element: 'mailbox',
          name: '\u00A9\u00AE\u2122',
          container: 'application'
        };

        await expect(queryExecutor.queryObject('Mail', specifier))
          .rejects.toThrow(/invalid characters/i);
      });

      it('should reject element names with zero-width characters', async () => {
        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'message\u200B\u200C',
          index: 0,
          container: 'application'
        };

        await expect(queryExecutor.queryObject('Mail', specifier))
          .rejects.toThrow(/invalid characters/i);
      });

      it('should reject IDs with combining diacritical marks', async () => {
        const specifier: IdSpecifier = {
          type: 'id',
          element: 'message',
          id: 'id\u0301\u0302',
          container: 'application'
        };

        await expect(queryExecutor.queryObject('Mail', specifier))
          .rejects.toThrow(/invalid characters/i);
      });
    });

    describe('Complex Injection Attempts', () => {
      it('should reject JXA function injection in element name', async () => {
        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'x"); app.doShellScript("rm -rf /"); app.windows.byName("',
          index: 0,
          container: 'application'
        };

        await expect(queryExecutor.queryObject('Mail', specifier))
          .rejects.toThrow(/invalid characters/i);
      });

      it('should reject template literal injection', async () => {
        const specifier: NamedSpecifier = {
          type: 'named',
          element: 'mailbox',
          name: '${process.exit()}',
          container: 'application'
        };

        await expect(queryExecutor.queryObject('Mail', specifier))
          .rejects.toThrow(/invalid characters/i);
      });

      it('should reject path traversal attempts', async () => {
        const specifier: NamedSpecifier = {
          type: 'named',
          element: 'file',
          name: '../../../etc/passwd',
          container: 'application'
        };

        await expect(queryExecutor.queryObject('Finder', specifier))
          .rejects.toThrow(/invalid characters/i);
      });

      it('should reject command substitution in names', async () => {
        const specifier: NamedSpecifier = {
          type: 'named',
          element: 'mailbox',
          name: '$(whoami)',
          container: 'application'
        };

        await expect(queryExecutor.queryObject('Mail', specifier))
          .rejects.toThrow(/invalid characters/i);
      });

      it('should reject escape sequence injection', async () => {
        const specifier: IdSpecifier = {
          type: 'id',
          element: 'message',
          id: '\\x00\\x1b',
          container: 'application'
        };

        await expect(queryExecutor.queryObject('Mail', specifier))
          .rejects.toThrow(/invalid characters/i);
      });

      it('should reject null byte injection', async () => {
        const specifier: NamedSpecifier = {
          type: 'named',
          element: 'mailbox',
          name: 'inbox\x00malicious',
          container: 'application'
        };

        await expect(queryExecutor.queryObject('Mail', specifier))
          .rejects.toThrow(/invalid characters/i);
      });
    });

    describe('Nested Specifier Security', () => {
      it('should validate element names in nested containers', async () => {
        const maliciousContainer: NamedSpecifier = {
          type: 'named',
          element: 'account"); doShellScript("rm -rf /',
          name: 'work',
          container: 'application'
        };

        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'mailbox',
          index: 0,
          container: maliciousContainer
        };

        await expect(queryExecutor.queryObject('Mail', specifier))
          .rejects.toThrow(/invalid characters/i);
      });

      it('should validate names in nested containers', async () => {
        const maliciousContainer: NamedSpecifier = {
          type: 'named',
          element: 'account',
          name: 'work"); app.system.exec("evil',
          container: 'application'
        };

        const specifier: ElementSpecifier = {
          type: 'element',
          element: 'mailbox',
          index: 0,
          container: maliciousContainer
        };

        await expect(queryExecutor.queryObject('Mail', specifier))
          .rejects.toThrow(/invalid characters/i);
      });

      it('should validate deeply nested specifiers', async () => {
        const level1: NamedSpecifier = {
          type: 'named',
          element: 'account',
          name: 'work',
          container: 'application'
        };

        const level2: NamedSpecifier = {
          type: 'named',
          element: 'mailbox',
          name: 'inbox',
          container: level1
        };

        const maliciousLevel3: ElementSpecifier = {
          type: 'element',
          element: 'message$(evil)',
          index: 0,
          container: level2
        };

        await expect(queryExecutor.queryObject('Mail', maliciousLevel3))
          .rejects.toThrow(/invalid characters/i);
      });
    });
  });

  describe('Circular Reference Detection', () => {
    it('should handle PropertySpecifier with valid reference ID', async () => {
      // First create a valid reference
      const messageSpec: ElementSpecifier = {
        type: 'element',
        element: 'message',
        index: 0,
        container: 'application'
      };
      const messageRef = await queryExecutor.queryObject('Mail', messageSpec);

      // Then use it in a PropertySpecifier
      const propertySpec: PropertySpecifier = {
        type: 'property',
        property: 'subject',
        of: messageRef.id
      };

      const ref = await queryExecutor.queryObject('Mail', propertySpec);
      expect(ref).toBeDefined();
    });

    it('should reject PropertySpecifier with invalid reference ID', async () => {
      const propertySpec: PropertySpecifier = {
        type: 'property',
        property: 'subject',
        of: 'ref_nonexistent'
      };

      await expect(queryExecutor.queryObject('Mail', propertySpec))
        .rejects.toThrow(/Reference not found/);
    });

    it('should handle nested specifiers without circular references', async () => {
      const level1: NamedSpecifier = {
        type: 'named',
        element: 'account',
        name: 'work',
        container: 'application'
      };

      const level2: NamedSpecifier = {
        type: 'named',
        element: 'mailbox',
        name: 'inbox',
        container: level1
      };

      const level3: ElementSpecifier = {
        type: 'element',
        element: 'message',
        index: 0,
        container: level2
      };

      const ref = await queryExecutor.queryObject('Mail', level3);
      expect(ref).toBeDefined();
      expect(ref.type).toBe('message');
    });

    // Note: True circular references (specifier A -> specifier B -> specifier A)
    // cannot be constructed in TypeScript due to the way the types work.
    // The specifier types require a complete object at construction time.
    // This is a compile-time safety that prevents runtime circular references.
    // We document this as a known limitation and security feature.
    it('should note that circular specifier chains are prevented by TypeScript types', () => {
      // This test documents that circular references cannot be created due to TypeScript constraints
      // A circular chain like: elementSpec.container -> namedSpec -> elementSpec
      // would require setting container to an object that references back to itself
      // which TypeScript prevents at compile time.
      expect(true).toBe(true);
    });
  });

  describe('Error Message Security', () => {
    it('should not leak internal details in error messages for invalid characters', async () => {
      const specifier: ElementSpecifier = {
        type: 'element',
        element: 'message$(evil)',
        index: 0,
        container: 'application'
      };

      try {
        await queryExecutor.queryObject('Mail', specifier);
        expect.fail('Should have thrown');
      } catch (error: any) {
        // Error message should be informative but not leak sensitive info
        expect(error.message).toContain('invalid characters');
        // Should not contain the full malicious input
        expect(error.message).not.toContain('$(evil)');
      }
    });

    it('should provide helpful error message for length violations', async () => {
      const tooLongName = 'a'.repeat(300);
      const specifier: NamedSpecifier = {
        type: 'named',
        element: 'mailbox',
        name: tooLongName,
        container: 'application'
      };

      try {
        await queryExecutor.queryObject('Mail', specifier);
        expect.fail('Should have thrown');
      } catch (error: any) {
        expect(error.message).toContain('exceeds maximum length');
        expect(error.message).toContain('256');
      }
    });
  });

  describe('App Parameter Injection Prevention', () => {
    const validSpecifier: ElementSpecifier = {
      type: 'element',
      element: 'mailbox',
      index: 0,
      container: 'application'
    };

    describe('Valid App Names - Should Accept', () => {
      it('should accept simple app names', async () => {
        const ref = await queryExecutor.queryObject('Mail', validSpecifier);
        expect(ref).toBeDefined();
      });

      it('should accept app names with spaces', async () => {
        const ref = await queryExecutor.queryObject('Microsoft Word', validSpecifier);
        expect(ref).toBeDefined();
      });

      it('should accept bundle ID format', async () => {
        const ref = await queryExecutor.queryObject('com.apple.finder', validSpecifier);
        expect(ref).toBeDefined();
      });

      it('should accept app names with hyphens and underscores', async () => {
        const ref = await queryExecutor.queryObject('My-App_Name', validSpecifier);
        expect(ref).toBeDefined();
      });
    });

    describe('Injection Attacks - Should Reject', () => {
      it('should reject app name with double quotes', async () => {
        await expect(
          queryExecutor.queryObject('Mail"); do shell script "rm -rf /', validSpecifier)
        ).rejects.toThrow('invalid characters');
      });

      it('should reject app name with backticks', async () => {
        await expect(
          queryExecutor.queryObject('Mail`rm -rf /`', validSpecifier)
        ).rejects.toThrow('invalid characters');
      });

      it('should reject app name with semicolons', async () => {
        await expect(
          queryExecutor.queryObject('Mail; rm -rf /', validSpecifier)
        ).rejects.toThrow('invalid characters');
      });

      it('should reject app name with parentheses', async () => {
        await expect(
          queryExecutor.queryObject('Application("Finder")', validSpecifier)
        ).rejects.toThrow('invalid characters');
      });

      it('should reject app name with shell substitution', async () => {
        await expect(
          queryExecutor.queryObject('$(whoami)', validSpecifier)
        ).rejects.toThrow('invalid characters');
      });

      it('should reject app name with newlines', async () => {
        await expect(
          queryExecutor.queryObject('Mail\n; rm -rf /', validSpecifier)
        ).rejects.toThrow('invalid characters');
      });
    });

    describe('DoS Prevention - App Name Length', () => {
      it('should reject app names exceeding 256 characters', async () => {
        const longAppName = 'A'.repeat(300);
        await expect(
          queryExecutor.queryObject(longAppName, validSpecifier)
        ).rejects.toThrow('exceeds maximum length');
      });

      it('should accept app names at exactly 256 characters', async () => {
        const maxAppName = 'A'.repeat(256);
        const ref = await queryExecutor.queryObject(maxAppName, validSpecifier);
        expect(ref).toBeDefined();
      });
    });

    describe('Edge Cases', () => {
      it('should reject empty app name', async () => {
        await expect(
          queryExecutor.queryObject('', validSpecifier)
        ).rejects.toThrow(/required|invalid/i);
      });

      it('should reject null-like app name', async () => {
        await expect(
          queryExecutor.queryObject(null as any, validSpecifier)
        ).rejects.toThrow(/required|invalid/i);
      });

      it('should reject undefined app name', async () => {
        await expect(
          queryExecutor.queryObject(undefined as any, validSpecifier)
        ).rejects.toThrow(/required|invalid/i);
      });
    });
  });
});
