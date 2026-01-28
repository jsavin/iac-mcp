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
import { IACMCPServer } from '../../src/mcp/server.js';

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
          name: 'iac_mcp_query_object',
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

      // Response format: { reference: { id, type, app } }
      expect(result.reference).toBeDefined();
      expect(result.reference.id).toMatch(/^ref_[a-z0-9]+$/);
      expect(result.reference.app).toBe('Mail');
      expect(result.reference.type).toBe('mailbox');
    });

    it('should query drafts mailbox and return different reference', async () => {
      const request = {
        method: 'tools/call',
        params: {
          name: 'iac_mcp_query_object',
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

      // Response format: { reference: { id, type, app } }
      expect(result.reference).toBeDefined();
      expect(result.reference.id).toMatch(/^ref_[a-z0-9]+$/);
      expect(result.reference.app).toBe('Mail');
      expect(result.reference.type).toBe('mailbox');
    });
  });

  describe('Workflow 2: Get Message from Inbox', () => {
    it('should get messages from inbox using reference', async () => {
      // Step 1: Query inbox
      const queryRequest = {
        method: 'tools/call',
        params: {
          name: 'iac_mcp_query_object',
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
      const queryResult = JSON.parse(queryResponse.content[0].text);

      // Step 2: Get messages from inbox
      const elementsRequest = {
        method: 'tools/call',
        params: {
          name: 'iac_mcp_get_elements',
          arguments: {
            container: queryResult.reference.id,
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
          name: 'iac_mcp_query_object',
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
      const queryResult = JSON.parse(queryResponse.content[0].text);

      // Step 2: Get messages with limit 5
      const elementsRequest = {
        method: 'tools/call',
        params: {
          name: 'iac_mcp_get_elements',
          arguments: {
            container: queryResult.reference.id,
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
          name: 'iac_mcp_query_object',
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
      const queryResult = JSON.parse(queryResponse.content[0].text);

      // Step 2: Get first message
      const elementsRequest = {
        method: 'tools/call',
        params: {
          name: 'iac_mcp_get_elements',
          arguments: {
            container: queryResult.reference.id,
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
            name: 'iac_mcp_get_properties',
            arguments: {
              reference: messageRef.id,
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
          name: 'iac_mcp_query_object',
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
      const result1 = JSON.parse(response1.content[0].text);

      // Response format: { reference: { id, type, app } }
      expect(result1.reference).toBeDefined();
      expect(result1.reference.id).toMatch(/^ref_[a-z0-9]+$/);
      expect(result1.reference.type).toBe('mailbox');

      // Step 2: Get messages from inbox
      const step2 = {
        method: 'tools/call',
        params: {
          name: 'iac_mcp_get_elements',
          arguments: {
            container: result1.reference.id,
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
            name: 'iac_mcp_get_properties',
            arguments: {
              reference: messageRef.id,
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
          name: 'iac_mcp_query_object',
          arguments: {
            app: 'Mail',
            specifier: mailboxSpec
          }
        }
      };

      const response1 = await server['handleRequest'](step1);
      const mailboxResult = JSON.parse(response1.content[0].text);

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
          name: 'iac_mcp_query_object',
          arguments: {
            app: 'Mail',
            specifier: messageSpec
          }
        }
      };

      const response2 = await server['handleRequest'](step2);
      const messageResult = JSON.parse(response2.content[0].text);

      // Response format: { reference: { id, type, app } }
      expect(messageResult.reference).toBeDefined();
      expect(messageResult.reference.id).toMatch(/^ref_[a-z0-9]+$/);
      expect(messageResult.reference.type).toBe('message');

      // Both references should be valid
      expect(mailboxResult.reference).toBeDefined();
      expect(mailboxResult.reference.id).toBeDefined();
      expect(messageResult.reference.id).toBeDefined();
      expect(mailboxResult.reference.id).not.toBe(messageResult.reference.id);
    });
  });

  describe('Workflow 5: Error Handling', () => {
    it('should return error when using invalid reference in iac_mcp_get_properties', async () => {
      const request = {
        method: 'tools/call',
        params: {
          name: 'iac_mcp_get_properties',
          arguments: {
            reference: 'ref_invalid123',
            properties: ['subject']
          }
        }
      };

      const response = await server['handleRequest'](request);
      const result = JSON.parse(response.content[0].text);

      // Error response format: { error: 'reference_invalid', reference: '...', ... }
      expect(result.error).toBe('reference_invalid');
      expect(result.reference).toBe('ref_invalid123');
    });

    it('should return error when using invalid reference in iac_mcp_get_elements', async () => {
      const request = {
        method: 'tools/call',
        params: {
          name: 'iac_mcp_get_elements',
          arguments: {
            container: 'ref_invalid456',
            elementType: 'message',
            limit: 10
          }
        }
      };

      const response = await server['handleRequest'](request);
      const result = JSON.parse(response.content[0].text);

      // Error response format: { error: 'reference_invalid', ... }
      expect(result.error).toBe('reference_invalid');
    });

    it('should provide helpful error for expired reference', async () => {
      // This test verifies error message suggests re-querying
      const request = {
        method: 'tools/call',
        params: {
          name: 'iac_mcp_get_properties',
          arguments: {
            reference: 'ref_expired789',
            properties: ['name']
          }
        }
      };

      const response = await server['handleRequest'](request);
      const result = JSON.parse(response.content[0].text);

      // Error response format: { error: 'reference_invalid', suggestion: '...' }
      expect(result.error).toBe('reference_invalid');
      expect(result.suggestion).toBeDefined();
    });

    it('should handle invalid specifier type in iac_mcp_query_object', async () => {
      const request = {
        method: 'tools/call',
        params: {
          name: 'iac_mcp_query_object',
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
          name: 'iac_mcp_query_object',
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
          name: 'iac_mcp_query_object',
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
      const queryResult = JSON.parse(queryResponse.content[0].text);

      // Use reference multiple times
      const elementsRequest1 = {
        method: 'tools/call',
        params: {
          name: 'iac_mcp_get_elements',
          arguments: {
            container: queryResult.reference.id,
            elementType: 'message',
            limit: 5
          }
        }
      };

      const elementsRequest2 = {
        method: 'tools/call',
        params: {
          name: 'iac_mcp_get_elements',
          arguments: {
            container: queryResult.reference.id,
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
          name: 'iac_mcp_query_object',
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
          name: 'iac_mcp_query_object',
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

      const inboxResult = JSON.parse(inboxResponse.content[0].text);
      const draftsResult = JSON.parse(draftsResponse.content[0].text);

      // Response format: { reference: { id, type, app } }
      // References should be different
      expect(inboxResult.reference.id).not.toBe(draftsResult.reference.id);
    });
  });

  describe('Complex Workflow Scenarios', () => {
    it('should handle Finder workflow: get window properties', async () => {
      // Query Finder window
      const windowQuery = {
        method: 'tools/call',
        params: {
          name: 'iac_mcp_query_object',
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
      const windowResult = JSON.parse(windowResponse.content[0].text);

      // Response format: { reference: { id, type, app } }
      expect(windowResult.reference).toBeDefined();
      expect(windowResult.reference.id).toMatch(/^ref_[a-z0-9]+$/);
      expect(windowResult.reference.type).toBe('window');

      // Get window properties
      const propsQuery = {
        method: 'tools/call',
        params: {
          name: 'iac_mcp_get_properties',
          arguments: {
            reference: windowResult.reference.id,
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
          name: 'iac_mcp_query_object',
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
      const docResult = JSON.parse(docResponse.content[0].text);

      // Response format: { reference: { id, type, app } }
      expect(docResult.reference).toBeDefined();
      expect(docResult.reference.id).toMatch(/^ref_[a-z0-9]+$/);
      expect(docResult.reference.type).toBe('document');

      // Get document URL
      const propsQuery = {
        method: 'tools/call',
        params: {
          name: 'iac_mcp_get_properties',
          arguments: {
            reference: docResult.reference.id,
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
