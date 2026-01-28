/**
 * Integration Tests for Query Tools MCP Integration
 *
 * Tests the MCP server integration for query tools:
 * - Query tools appear in ListTools response
 * - Correct number of tools (3 query tools + existing tools)
 * - Tool schemas are correct
 * - CallTool routes to correct handlers
 * - Error responses have correct format
 *
 * These tests verify that query tools are properly registered and
 * integrated with the MCP server protocol.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { IACMCPServer } from '../../src/mcp/iac-mcp-server.js';
import { ListToolsRequestSchema, CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import type { MCPTool } from '../../src/types/mcp-tool.js';

describe('Query Tools MCP Integration', () => {
  let server: IACMCPServer;

  beforeEach(async () => {
    server = new IACMCPServer({ enableLogging: false });
    await server.initialize();
    await server.start();
  });

  afterEach(async () => {
    await server.stop();
  });

  describe('ListTools Integration', () => {
    it('should include query tools in ListTools response', async () => {
      const request = {
        method: 'tools/list',
        params: {}
      };

      const response = await server['handleRequest'](request);
      const tools = response.tools as MCPTool[];

      // Find query tools
      const queryObjectTool = tools.find(t => t.name === 'query_object');
      const getPropertiesTool = tools.find(t => t.name === 'get_properties');
      const getElementsTool = tools.find(t => t.name === 'get_elements');

      expect(queryObjectTool).toBeDefined();
      expect(getPropertiesTool).toBeDefined();
      expect(getElementsTool).toBeDefined();
    });

    it('should have correct schemas for query_object tool', async () => {
      const request = {
        method: 'tools/list',
        params: {}
      };

      const response = await server['handleRequest'](request);
      const tools = response.tools as MCPTool[];
      const queryObjectTool = tools.find(t => t.name === 'query_object');

      expect(queryObjectTool).toBeDefined();
      expect(queryObjectTool!.name).toBe('query_object');
      expect(queryObjectTool!.description).toContain('Query an object');
      expect(queryObjectTool!.inputSchema).toBeDefined();
      expect(queryObjectTool!.inputSchema.type).toBe('object');
      expect(queryObjectTool!.inputSchema.properties).toHaveProperty('app');
      expect(queryObjectTool!.inputSchema.properties).toHaveProperty('specifier');
      expect(queryObjectTool!.inputSchema.required).toContain('app');
      expect(queryObjectTool!.inputSchema.required).toContain('specifier');
    });

    it('should have correct schemas for get_properties tool', async () => {
      const request = {
        method: 'tools/list',
        params: {}
      };

      const response = await server['handleRequest'](request);
      const tools = response.tools as MCPTool[];
      const getPropertiesTool = tools.find(t => t.name === 'get_properties');

      expect(getPropertiesTool).toBeDefined();
      expect(getPropertiesTool!.name).toBe('get_properties');
      expect(getPropertiesTool!.description).toContain('Get properties');
      expect(getPropertiesTool!.inputSchema).toBeDefined();
      expect(getPropertiesTool!.inputSchema.type).toBe('object');
      expect(getPropertiesTool!.inputSchema.properties).toHaveProperty('referenceId');
      expect(getPropertiesTool!.inputSchema.properties).toHaveProperty('properties');
      expect(getPropertiesTool!.inputSchema.required).toContain('referenceId');
    });

    it('should have correct schemas for get_elements tool', async () => {
      const request = {
        method: 'tools/list',
        params: {}
      };

      const response = await server['handleRequest'](request);
      const tools = response.tools as MCPTool[];
      const getElementsTool = tools.find(t => t.name === 'get_elements');

      expect(getElementsTool).toBeDefined();
      expect(getElementsTool!.name).toBe('get_elements');
      expect(getElementsTool!.description).toContain('Get elements');
      expect(getElementsTool!.inputSchema).toBeDefined();
      expect(getElementsTool!.inputSchema.type).toBe('object');
      expect(getElementsTool!.inputSchema.properties).toHaveProperty('container');
      expect(getElementsTool!.inputSchema.properties).toHaveProperty('elementType');
      expect(getElementsTool!.inputSchema.properties).toHaveProperty('limit');
      expect(getElementsTool!.inputSchema.required).toContain('container');
      expect(getElementsTool!.inputSchema.required).toContain('elementType');
    });

    it('should include query tools alongside existing app tools', async () => {
      const request = {
        method: 'tools/list',
        params: {}
      };

      const response = await server['handleRequest'](request);
      const tools = response.tools as MCPTool[];

      // Should have query tools
      const queryTools = tools.filter(t =>
        t.name === 'query_object' ||
        t.name === 'get_properties' ||
        t.name === 'get_elements'
      );
      expect(queryTools).toHaveLength(3);

      // Should also have list_apps tool
      const listAppsTool = tools.find(t => t.name === 'list_apps');
      expect(listAppsTool).toBeDefined();
    });
  });

  describe('CallTool Integration - query_object', () => {
    it('should handle query_object with NamedSpecifier', async () => {
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

      expect(response.content).toBeDefined();
      expect(response.content).toHaveLength(1);
      expect(response.content[0].type).toBe('text');

      const result = JSON.parse(response.content[0].text);
      expect(result.id).toMatch(/^ref_[a-z0-9]+$/);
      expect(result.app).toBe('Mail');
      expect(result.type).toBe('mailbox');
      expect(result.specifier).toEqual({
        type: 'named',
        element: 'mailbox',
        name: 'inbox',
        container: 'application'
      });
    });

    it('should handle query_object with ElementSpecifier', async () => {
      const request = {
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

      const response = await server['handleRequest'](request);

      expect(response.content).toBeDefined();
      expect(response.content).toHaveLength(1);
      expect(response.content[0].type).toBe('text');

      const result = JSON.parse(response.content[0].text);
      expect(result.id).toMatch(/^ref_[a-z0-9]+$/);
      expect(result.app).toBe('Finder');
      expect(result.type).toBe('window');
    });

    it('should return error for unsupported specifier type', async () => {
      const request = {
        method: 'tools/call',
        params: {
          name: 'query_object',
          arguments: {
            app: 'Mail',
            specifier: {
              type: 'unsupported',
              element: 'message'
            }
          }
        }
      };

      const response = await server['handleRequest'](request);

      expect(response.content).toBeDefined();
      expect(response.content).toHaveLength(1);
      expect(response.content[0].type).toBe('text');

      const result = response.content[0].text;
      expect(result).toContain('Unsupported specifier type');
    });
  });

  describe('CallTool Integration - get_properties', () => {
    it('should handle get_properties with valid reference', async () => {
      // First create a reference
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
      const reference = JSON.parse(queryResponse.content[0].text);

      // Now get properties
      const propsRequest = {
        method: 'tools/call',
        params: {
          name: 'get_properties',
          arguments: {
            referenceId: reference.id,
            properties: ['name', 'unreadCount']
          }
        }
      };

      const response = await server['handleRequest'](propsRequest);

      expect(response.content).toBeDefined();
      expect(response.content).toHaveLength(1);
      expect(response.content[0].type).toBe('text');

      // Response should be JSON (even if empty in Phase 1)
      const result = JSON.parse(response.content[0].text);
      expect(result).toBeDefined();
    });

    it('should return error for invalid reference ID', async () => {
      const request = {
        method: 'tools/call',
        params: {
          name: 'get_properties',
          arguments: {
            referenceId: 'ref_invalid123',
            properties: ['name']
          }
        }
      };

      const response = await server['handleRequest'](request);

      expect(response.content).toBeDefined();
      expect(response.content).toHaveLength(1);
      expect(response.content[0].type).toBe('text');

      const result = response.content[0].text;
      expect(result).toContain('Reference not found');
    });
  });

  describe('CallTool Integration - get_elements', () => {
    it('should handle get_elements with reference ID', async () => {
      // First create a mailbox reference
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
      const mailboxRef = JSON.parse(queryResponse.content[0].text);

      // Now get messages from mailbox
      const elementsRequest = {
        method: 'tools/call',
        params: {
          name: 'get_elements',
          arguments: {
            container: mailboxRef.id,
            elementType: 'message',
            limit: 5
          }
        }
      };

      const response = await server['handleRequest'](elementsRequest);

      expect(response.content).toBeDefined();
      expect(response.content).toHaveLength(1);
      expect(response.content[0].type).toBe('text');

      const result = JSON.parse(response.content[0].text);
      expect(result).toHaveProperty('elements');
      expect(result).toHaveProperty('count');
      expect(result).toHaveProperty('hasMore');
      expect(Array.isArray(result.elements)).toBe(true);
    });

    it('should handle get_elements with specifier', async () => {
      const request = {
        method: 'tools/call',
        params: {
          name: 'get_elements',
          arguments: {
            container: {
              type: 'named',
              element: 'mailbox',
              name: 'inbox',
              container: 'application'
            },
            elementType: 'message',
            limit: 10
          }
        }
      };

      const response = await server['handleRequest'](request);

      expect(response.content).toBeDefined();
      expect(response.content).toHaveLength(1);
      expect(response.content[0].type).toBe('text');

      const result = JSON.parse(response.content[0].text);
      expect(result).toHaveProperty('elements');
      expect(result).toHaveProperty('count');
      expect(result).toHaveProperty('hasMore');
    });

    it('should return error for invalid reference ID', async () => {
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

      expect(response.content).toBeDefined();
      expect(response.content).toHaveLength(1);
      expect(response.content[0].type).toBe('text');

      const result = response.content[0].text;
      expect(result).toContain('Reference not found');
    });
  });

  describe('Error Handling', () => {
    it('should return properly formatted error for missing app parameter', async () => {
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

      expect(response.content).toBeDefined();
      expect(response.content).toHaveLength(1);
      expect(response.content[0].type).toBe('text');
      // Error should be clear about missing parameter
      const result = response.content[0].text;
      expect(result).toBeTruthy();
    });

    it('should return properly formatted error for missing specifier parameter', async () => {
      const request = {
        method: 'tools/call',
        params: {
          name: 'query_object',
          arguments: {
            app: 'Mail'
            // Missing 'specifier' parameter
          }
        }
      };

      const response = await server['handleRequest'](request);

      expect(response.content).toBeDefined();
      expect(response.content).toHaveLength(1);
      expect(response.content[0].type).toBe('text');
      const result = response.content[0].text;
      expect(result).toBeTruthy();
    });

    it('should handle invalid tool name gracefully', async () => {
      const request = {
        method: 'tools/call',
        params: {
          name: 'invalid_query_tool',
          arguments: {}
        }
      };

      const response = await server['handleRequest'](request);

      expect(response.content).toBeDefined();
      expect(response.content).toHaveLength(1);
      expect(response.content[0].type).toBe('text');
      expect(response.isError).toBe(true);
    });
  });
});
