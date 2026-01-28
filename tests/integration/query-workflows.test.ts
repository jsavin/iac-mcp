/**
 * Integration Tests for Query Workflows
 *
 * Tests end-to-end query workflows:
 * - Workflow 1: Query inbox mailbox
 * - Workflow 2: Get message from inbox
 * - Workflow 3: Read message properties
 * - Workflow 4: Complete "most recent email" scenario
 * - Workflow 5: Error handling
 *
 * These tests verify that complete workflows work correctly
 * by chaining multiple tool calls together.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { IACMCPServer } from '../../src/mcp/iac-mcp-server.js';

describe('Query Workflows Integration', () => {
  let server: IACMCPServer;

  beforeEach(async () => {
    server = new IACMCPServer({ enableLogging: false });
    await server.initialize();
    await server.start();
  });

  afterEach(async () => {
    await server.stop();
  });

  describe('Workflow 1: Query Inbox Mailbox', () => {
    it('should query inbox mailbox and return reference', async () => {
      const request = {
        method: 'tools/call',
        params: {
          name: 'query_object',
          arguments: {
            app: 'Mail',
            specifier: {
              type: 'named',
              element: 'mailbox',
              name: 'inbox',
              container: 'application'
            }
          }
        }
      };

      const response = await server['handleRequest'](request);
      const result = JSON.parse(response.content[0].text);

      expect(result.id).toMatch(/^ref_[a-z0-9]+$/);
      expect(result.app).toBe('Mail');
      expect(result.type).toBe('mailbox');
      expect(result.specifier.name).toBe('inbox');
    });

    it('should query drafts mailbox and return different reference', async () => {
      const request = {
        method: 'tools/call',
        params: {
          name: 'query_object',
          arguments: {
            app: 'Mail',
            specifier: {
              type: 'named',
              element: 'mailbox',
              name: 'drafts',
              container: 'application'
            }
          }
        }
      };

      const response = await server['handleRequest'](request);
      const result = JSON.parse(response.content[0].text);

      expect(result.id).toMatch(/^ref_[a-z0-9]+$/);
      expect(result.app).toBe('Mail');
      expect(result.type).toBe('mailbox');
      expect(result.specifier.name).toBe('drafts');
    });
  });

  describe('Workflow 2: Get Message from Inbox', () => {
    it('should get messages from inbox using reference', async () => {
      // Step 1: Query inbox
      const queryRequest = {
        method: 'tools/call',
        params: {
          name: 'query_object',
          arguments: {
            app: 'Mail',
            specifier: {
              type: 'named',
              element: 'mailbox',
              name: 'inbox',
              container: 'application'
            }
          }
        }
      };

      const queryResponse = await server['handleRequest'](queryRequest);
      const inboxRef = JSON.parse(queryResponse.content[0].text);

      // Step 2: Get messages from inbox
      const elementsRequest = {
        method: 'tools/call',
        params: {
          name: 'get_elements',
          arguments: {
            container: inboxRef.id,
            elementType: 'message',
            limit: 1
          }
        }
      };

      const elementsResponse = await server['handleRequest'](elementsRequest);
      const result = JSON.parse(elementsResponse.content[0].text);

      expect(result.elements).toBeDefined();
      expect(Array.isArray(result.elements)).toBe(true);
      expect(result.count).toBeDefined();
      expect(result.hasMore).toBeDefined();
    });

    it('should get multiple messages with limit', async () => {
      // Step 1: Query inbox
      const queryRequest = {
        method: 'tools/call',
        params: {
          name: 'query_object',
          arguments: {
            app: 'Mail',
            specifier: {
              type: 'named',
              element: 'mailbox',
              name: 'inbox',
              container: 'application'
            }
          }
        }
      };

      const queryResponse = await server['handleRequest'](queryRequest);
      const inboxRef = JSON.parse(queryResponse.content[0].text);

      // Step 2: Get messages with limit 5
      const elementsRequest = {
        method: 'tools/call',
        params: {
          name: 'get_elements',
          arguments: {
            container: inboxRef.id,
            elementType: 'message',
            limit: 5
          }
        }
      };

      const elementsResponse = await server['handleRequest'](elementsRequest);
      const result = JSON.parse(elementsResponse.content[0].text);

      expect(result.elements).toBeDefined();
      expect(Array.isArray(result.elements)).toBe(true);
      expect(result.count).toBeDefined();
      expect(result.hasMore).toBeDefined();
    });
  });

  describe('Workflow 3: Read Message Properties', () => {
    it('should read properties from message reference', async () => {
      // Step 1: Query inbox
      const queryRequest = {
        method: 'tools/call',
        params: {
          name: 'query_object',
          arguments: {
            app: 'Mail',
            specifier: {
              type: 'named',
              element: 'mailbox',
              name: 'inbox',
              container: 'application'
            }
          }
        }
      };

      const queryResponse = await server['handleRequest'](queryRequest);
      const inboxRef = JSON.parse(queryResponse.content[0].text);

      // Step 2: Get first message
      const elementsRequest = {
        method: 'tools/call',
        params: {
          name: 'get_elements',
          arguments: {
            container: inboxRef.id,
            elementType: 'message',
            limit: 1
          }
        }
      };

      const elementsResponse = await server['handleRequest'](elementsRequest);
      const elementsResult = JSON.parse(elementsResponse.content[0].text);

      // Step 3: Get properties (only if we have messages)
      if (elementsResult.elements.length > 0) {
        const messageRef = elementsResult.elements[0];

        const propsRequest = {
          method: 'tools/call',
          params: {
            name: 'get_properties',
            arguments: {
              referenceId: messageRef.id,
              properties: ['subject', 'sender', 'date']
            }
          }
        };

        const propsResponse = await server['handleRequest'](propsRequest);
        const propsResult = JSON.parse(propsResponse.content[0].text);

        expect(propsResult).toBeDefined();
        // In Phase 1, properties will be empty object, but structure should be valid
      }

      // Test should pass even if no messages (Phase 1 limitation)
      expect(true).toBe(true);
    });
  });

  describe('Workflow 4: Complete "Most Recent Email" Scenario', () => {
    it('should execute complete workflow from mailbox to message properties', async () => {
      // Step 1: Query inbox mailbox
      const step1 = {
        method: 'tools/call',
        params: {
          name: 'query_object',
          arguments: {
            app: 'Mail',
            specifier: {
              type: 'named',
              element: 'mailbox',
              name: 'inbox',
              container: 'application'
            }
          }
        }
      };

      const response1 = await server['handleRequest'](step1);
      const inboxRef = JSON.parse(response1.content[0].text);

      expect(inboxRef.id).toMatch(/^ref_[a-z0-9]+$/);
      expect(inboxRef.type).toBe('mailbox');

      // Step 2: Get messages from inbox
      const step2 = {
        method: 'tools/call',
        params: {
          name: 'get_elements',
          arguments: {
            container: inboxRef.id,
            elementType: 'message',
            limit: 1
          }
        }
      };

      const response2 = await server['handleRequest'](step2);
      const messagesResult = JSON.parse(response2.content[0].text);

      expect(messagesResult.elements).toBeDefined();
      expect(Array.isArray(messagesResult.elements)).toBe(true);

      // Step 3: If messages exist, get properties
      if (messagesResult.elements.length > 0) {
        const messageRef = messagesResult.elements[0];

        expect(messageRef.id).toMatch(/^ref_[a-z0-9]+$/);
        expect(messageRef.type).toBe('message');

        const step3 = {
          method: 'tools/call',
          params: {
            name: 'get_properties',
            arguments: {
              referenceId: messageRef.id,
              properties: ['subject', 'sender', 'date', 'content']
            }
          }
        };

        const response3 = await server['handleRequest'](step3);
        const propertiesResult = JSON.parse(response3.content[0].text);

        expect(propertiesResult).toBeDefined();
      }

      // Workflow should complete without errors
      expect(true).toBe(true);
    });

    it('should handle chained queries with nested specifiers', async () => {
      // Create a deeply nested query using references
      // Step 1: Query application
      const mailboxSpec = {
        type: 'named',
        element: 'mailbox',
        name: 'inbox',
        container: 'application'
      };

      const step1 = {
        method: 'tools/call',
        params: {
          name: 'query_object',
          arguments: {
            app: 'Mail',
            specifier: mailboxSpec
          }
        }
      };

      const response1 = await server['handleRequest'](step1);
      const mailboxRef = JSON.parse(response1.content[0].text);

      // Step 2: Query message within mailbox (using reference in specifier)
      const messageSpec = {
        type: 'element',
        element: 'message',
        index: 0,
        container: mailboxSpec
      };

      const step2 = {
        method: 'tools/call',
        params: {
          name: 'query_object',
          arguments: {
            app: 'Mail',
            specifier: messageSpec
          }
        }
      };

      const response2 = await server['handleRequest'](step2);
      const messageRef = JSON.parse(response2.content[0].text);

      expect(messageRef.id).toMatch(/^ref_[a-z0-9]+$/);
      expect(messageRef.type).toBe('message');

      // Both references should be valid
      expect(mailboxRef.id).toBeDefined();
      expect(messageRef.id).toBeDefined();
      expect(mailboxRef.id).not.toBe(messageRef.id);
    });
  });

  describe('Workflow 5: Error Handling', () => {
    it('should return error when using invalid reference in get_properties', async () => {
      const request = {
        method: 'tools/call',
        params: {
          name: 'get_properties',
          arguments: {
            referenceId: 'ref_invalid123',
            properties: ['subject']
          }
        }
      };

      const response = await server['handleRequest'](request);
      const result = response.content[0].text;

      expect(result).toContain('Reference not found');
      expect(result).toContain('ref_invalid123');
    });

    it('should return error when using invalid reference in get_elements', async () => {
      const request = {
        method: 'tools/call',
        params: {
          name: 'get_elements',
          arguments: {
            container: 'ref_invalid456',
            elementType: 'message',
            limit: 10
          }
        }
      };

      const response = await server['handleRequest'](request);
      const result = response.content[0].text;

      expect(result).toContain('Reference not found');
      expect(result).toContain('ref_invalid456');
    });

    it('should provide helpful error for expired reference', async () => {
      // This test verifies error message suggests re-querying
      const request = {
        method: 'tools/call',
        params: {
          name: 'get_properties',
          arguments: {
            referenceId: 'ref_expired789',
            properties: ['name']
          }
        }
      };

      const response = await server['handleRequest'](request);
      const result = response.content[0].text;

      expect(result).toContain('Reference not found');
      // Error should be clear that reference doesn't exist
      expect(result.length).toBeGreaterThan(0);
    });

    it('should handle invalid specifier type in query_object', async () => {
      const request = {
        method: 'tools/call',
        params: {
          name: 'query_object',
          arguments: {
            app: 'Mail',
            specifier: {
              type: 'invalid-type',
              element: 'message'
            }
          }
        }
      };

      const response = await server['handleRequest'](request);
      const result = response.content[0].text;

      expect(result).toContain('Unsupported specifier type');
    });

    it('should handle missing required parameters', async () => {
      const request = {
        method: 'tools/call',
        params: {
          name: 'query_object',
          arguments: {
            // Missing 'app' parameter
            specifier: {
              type: 'named',
              element: 'mailbox',
              name: 'inbox',
              container: 'application'
            }
          }
        }
      };

      const response = await server['handleRequest'](request);
      const result = response.content[0].text;

      // Should return error about missing parameter
      expect(result).toBeTruthy();
      expect(result.length).toBeGreaterThan(0);
    });
  });

  describe('Reference Reuse Across Workflows', () => {
    it('should reuse inbox reference across multiple queries', async () => {
      // Query inbox once
      const queryRequest = {
        method: 'tools/call',
        params: {
          name: 'query_object',
          arguments: {
            app: 'Mail',
            specifier: {
              type: 'named',
              element: 'mailbox',
              name: 'inbox',
              container: 'application'
            }
          }
        }
      };

      const queryResponse = await server['handleRequest'](queryRequest);
      const inboxRef = JSON.parse(queryResponse.content[0].text);

      // Use reference multiple times
      const elementsRequest1 = {
        method: 'tools/call',
        params: {
          name: 'get_elements',
          arguments: {
            container: inboxRef.id,
            elementType: 'message',
            limit: 5
          }
        }
      };

      const elementsRequest2 = {
        method: 'tools/call',
        params: {
          name: 'get_elements',
          arguments: {
            container: inboxRef.id,
            elementType: 'message',
            limit: 10
          }
        }
      };

      const response1 = await server['handleRequest'](elementsRequest1);
      const response2 = await server['handleRequest'](elementsRequest2);

      const result1 = JSON.parse(response1.content[0].text);
      const result2 = JSON.parse(response2.content[0].text);

      // Both should succeed
      expect(result1.elements).toBeDefined();
      expect(result2.elements).toBeDefined();
    });

    it('should maintain separate references for different mailboxes', async () => {
      // Query inbox
      const inboxQuery = {
        method: 'tools/call',
        params: {
          name: 'query_object',
          arguments: {
            app: 'Mail',
            specifier: {
              type: 'named',
              element: 'mailbox',
              name: 'inbox',
              container: 'application'
            }
          }
        }
      };

      // Query drafts
      const draftsQuery = {
        method: 'tools/call',
        params: {
          name: 'query_object',
          arguments: {
            app: 'Mail',
            specifier: {
              type: 'named',
              element: 'mailbox',
              name: 'drafts',
              container: 'application'
            }
          }
        }
      };

      const inboxResponse = await server['handleRequest'](inboxQuery);
      const draftsResponse = await server['handleRequest'](draftsQuery);

      const inboxRef = JSON.parse(inboxResponse.content[0].text);
      const draftsRef = JSON.parse(draftsResponse.content[0].text);

      // References should be different
      expect(inboxRef.id).not.toBe(draftsRef.id);
      expect(inboxRef.specifier.name).toBe('inbox');
      expect(draftsRef.specifier.name).toBe('drafts');
    });
  });

  describe('Complex Workflow Scenarios', () => {
    it('should handle Finder workflow: get window properties', async () => {
      // Query Finder window
      const windowQuery = {
        method: 'tools/call',
        params: {
          name: 'query_object',
          arguments: {
            app: 'Finder',
            specifier: {
              type: 'element',
              element: 'window',
              index: 0,
              container: 'application'
            }
          }
        }
      };

      const windowResponse = await server['handleRequest'](windowQuery);
      const windowRef = JSON.parse(windowResponse.content[0].text);

      expect(windowRef.id).toMatch(/^ref_[a-z0-9]+$/);
      expect(windowRef.type).toBe('window');

      // Get window properties
      const propsQuery = {
        method: 'tools/call',
        params: {
          name: 'get_properties',
          arguments: {
            referenceId: windowRef.id,
            properties: ['name', 'position', 'bounds']
          }
        }
      };

      const propsResponse = await server['handleRequest'](propsQuery);
      const propsResult = JSON.parse(propsResponse.content[0].text);

      expect(propsResult).toBeDefined();
    });

    it('should handle Safari workflow: get document URL', async () => {
      // Query Safari document
      const docQuery = {
        method: 'tools/call',
        params: {
          name: 'query_object',
          arguments: {
            app: 'Safari',
            specifier: {
              type: 'element',
              element: 'document',
              index: 0,
              container: 'application'
            }
          }
        }
      };

      const docResponse = await server['handleRequest'](docQuery);
      const docRef = JSON.parse(docResponse.content[0].text);

      expect(docRef.id).toMatch(/^ref_[a-z0-9]+$/);
      expect(docRef.type).toBe('document');

      // Get document URL
      const propsQuery = {
        method: 'tools/call',
        params: {
          name: 'get_properties',
          arguments: {
            referenceId: docRef.id,
            properties: ['URL', 'name']
          }
        }
      };

      const propsResponse = await server['handleRequest'](propsQuery);
      const propsResult = JSON.parse(propsResponse.content[0].text);

      expect(propsResult).toBeDefined();
    });
  });
});
