/**
 * Integration Tests for Query Tools MCP Integration
 *
 * Tests the MCP server integration for query tools:
 * - Query tools appear in ListTools response
 * - Correct number of tools (4 query tools + existing tools)
 * - Tool schemas are correct
 * - CallTool routes to correct handlers
 * - Error responses have correct format
 *
 * These tests verify that query tools are properly registered and
 * integrated with the MCP server protocol.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { IACMCPServer } from '../../src/mcp/server.js';
import type { MCPTool } from '../../src/types/mcp-tool.js';

describe('Query Tools MCP Integration', () => {
  let server: IACMCPServer;

  beforeEach(async () => {
    // Use disableJxaExecution: true to avoid real app interactions in tests
    server = new IACMCPServer({ enableLogging: false, disableJxaExecution: true });
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
      const queryObjectTool = tools.find(t => t.name === 'iac_mcp_query_object');
      const getPropertiesTool = tools.find(t => t.name === 'iac_mcp_get_properties');
      const setPropertyTool = tools.find(t => t.name === 'iac_mcp_set_property');
      const getElementsTool = tools.find(t => t.name === 'iac_mcp_get_elements');

      expect(queryObjectTool).toBeDefined();
      expect(getPropertiesTool).toBeDefined();
      expect(setPropertyTool).toBeDefined();
      expect(getElementsTool).toBeDefined();
    });

    it('should have correct schemas for iac_mcp_query_object tool', async () => {
      const request = {
        method: 'tools/list',
        params: {}
      };

      const response = await server['handleRequest'](request);
      const tools = response.tools as MCPTool[];
      const queryObjectTool = tools.find(t => t.name === 'iac_mcp_query_object');

      expect(queryObjectTool).toBeDefined();
      expect(queryObjectTool!.name).toBe('iac_mcp_query_object');
      expect(queryObjectTool!.description).toContain('Query an object');
      expect(queryObjectTool!.inputSchema).toBeDefined();
      expect(queryObjectTool!.inputSchema.type).toBe('object');
      expect(queryObjectTool!.inputSchema.properties).toHaveProperty('app');
      expect(queryObjectTool!.inputSchema.properties).toHaveProperty('specifier');
      expect(queryObjectTool!.inputSchema.required).toContain('app');
      expect(queryObjectTool!.inputSchema.required).toContain('specifier');
    });

    it('should have correct schemas for iac_mcp_get_properties tool', async () => {
      const request = {
        method: 'tools/list',
        params: {}
      };

      const response = await server['handleRequest'](request);
      const tools = response.tools as MCPTool[];
      const getPropertiesTool = tools.find(t => t.name === 'iac_mcp_get_properties');

      expect(getPropertiesTool).toBeDefined();
      expect(getPropertiesTool!.name).toBe('iac_mcp_get_properties');
      expect(getPropertiesTool!.description).toContain('Get properties');
      expect(getPropertiesTool!.inputSchema).toBeDefined();
      expect(getPropertiesTool!.inputSchema.type).toBe('object');
      expect(getPropertiesTool!.inputSchema.properties).toHaveProperty('reference');
      expect(getPropertiesTool!.inputSchema.properties).toHaveProperty('properties');
      expect(getPropertiesTool!.inputSchema.required).toContain('reference');
    });

    it('should have correct schemas for iac_mcp_set_property tool', async () => {
      const request = {
        method: 'tools/list',
        params: {}
      };

      const response = await server['handleRequest'](request);
      const tools = response.tools as MCPTool[];
      const setPropertyTool = tools.find(t => t.name === 'iac_mcp_set_property');

      expect(setPropertyTool).toBeDefined();
      expect(setPropertyTool!.name).toBe('iac_mcp_set_property');
      expect(setPropertyTool!.description).toContain('Set a property');
      expect(setPropertyTool!.inputSchema).toBeDefined();
      expect(setPropertyTool!.inputSchema.type).toBe('object');
      expect(setPropertyTool!.inputSchema.properties).toHaveProperty('reference');
      expect(setPropertyTool!.inputSchema.properties).toHaveProperty('property');
      expect(setPropertyTool!.inputSchema.properties).toHaveProperty('value');
      expect(setPropertyTool!.inputSchema.required).toContain('reference');
      expect(setPropertyTool!.inputSchema.required).toContain('property');
      expect(setPropertyTool!.inputSchema.required).toContain('value');
    });

    it('should have correct schemas for iac_mcp_get_elements tool', async () => {
      const request = {
        method: 'tools/list',
        params: {}
      };

      const response = await server['handleRequest'](request);
      const tools = response.tools as MCPTool[];
      const getElementsTool = tools.find(t => t.name === 'iac_mcp_get_elements');

      expect(getElementsTool).toBeDefined();
      expect(getElementsTool!.name).toBe('iac_mcp_get_elements');
      expect(getElementsTool!.description).toContain('Get child elements');
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
        t.name === 'iac_mcp_query_object' ||
        t.name === 'iac_mcp_get_properties' ||
        t.name === 'iac_mcp_set_property' ||
        t.name === 'iac_mcp_get_elements' ||
        t.name === 'iac_mcp_get_elements_with_properties' ||
        t.name === 'iac_mcp_get_properties_batch'
      );
      expect(queryTools).toHaveLength(6);

      // Should also have list_apps tool
      const listAppsTool = tools.find(t => t.name === 'list_apps');
      expect(listAppsTool).toBeDefined();
    });
  });

  describe('CallTool Integration - iac_mcp_query_object', () => {
    it('should handle iac_mcp_query_object with NamedSpecifier', async () => {
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

      expect(response.content).toBeDefined();
      expect(response.content).toHaveLength(1);
      expect(response.content[0].type).toBe('text');

      const result = JSON.parse(response.content[0].text);
      // Response format: { reference: { id, type, app } }
      expect(result.reference).toBeDefined();
      expect(result.reference.id).toMatch(/^ref_[a-f0-9-]+$/);  // UUID format
      expect(result.reference.app).toBe('Mail');
      expect(result.reference.type).toBe('mailbox');
    });

    it('should handle iac_mcp_query_object with ElementSpecifier', async () => {
      const request = {
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

      const response = await server['handleRequest'](request);

      expect(response.content).toBeDefined();
      expect(response.content).toHaveLength(1);
      expect(response.content[0].type).toBe('text');

      const result = JSON.parse(response.content[0].text);
      // Response format: { reference: { id, type, app } }
      expect(result.reference).toBeDefined();
      expect(result.reference.id).toMatch(/^ref_[a-f0-9-]+$/);  // UUID format
      expect(result.reference.app).toBe('Finder');
      expect(result.reference.type).toBe('window');
    });

    it('should return error for unsupported specifier type', async () => {
      const request = {
        method: 'tools/call',
        params: {
          name: 'iac_mcp_query_object',
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

      const result = JSON.parse(response.content[0].text);
      // With runtime validation, invalid specifier type returns validation error
      expect(result.error).toBe('invalid_parameter');
    });
  });

  describe('CallTool Integration - iac_mcp_get_properties', () => {
    it('should handle iac_mcp_get_properties with valid reference', async () => {
      // First create a reference
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

      // Now get properties
      const propsRequest = {
        method: 'tools/call',
        params: {
          name: 'iac_mcp_get_properties',
          arguments: {
            reference: queryResult.reference.id,
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
          name: 'iac_mcp_get_properties',
          arguments: {
            reference: 'ref_invalid123',
            properties: ['name']
          }
        }
      };

      const response = await server['handleRequest'](request);

      expect(response.content).toBeDefined();
      expect(response.content).toHaveLength(1);
      expect(response.content[0].type).toBe('text');

      const result = JSON.parse(response.content[0].text);
      // Error response format: { error: 'reference_not_found', ... }
      expect(result.error).toBe('reference_not_found');
    });
  });

  describe('CallTool Integration - iac_mcp_set_property', () => {
    it('should handle iac_mcp_set_property with valid reference', async () => {
      // First create a reference
      const queryRequest = {
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

      const queryResponse = await server['handleRequest'](queryRequest);
      const queryResult = JSON.parse(queryResponse.content[0].text);

      // Now set a property
      const setRequest = {
        method: 'tools/call',
        params: {
          name: 'iac_mcp_set_property',
          arguments: {
            reference: queryResult.reference.id,
            property: 'visible',
            value: true
          }
        }
      };

      const response = await server['handleRequest'](setRequest);

      expect(response.content).toBeDefined();
      expect(response.content).toHaveLength(1);
      expect(response.content[0].type).toBe('text');

      // Response should be JSON (success or error - JXA disabled in tests)
      const result = JSON.parse(response.content[0].text);
      expect(result).toBeDefined();
    });

    it('should return error for invalid reference ID', async () => {
      const request = {
        method: 'tools/call',
        params: {
          name: 'iac_mcp_set_property',
          arguments: {
            reference: 'ref_invalid789',
            property: 'visible',
            value: true
          }
        }
      };

      const response = await server['handleRequest'](request);

      expect(response.content).toBeDefined();
      expect(response.content).toHaveLength(1);
      expect(response.content[0].type).toBe('text');

      const result = JSON.parse(response.content[0].text);
      // Error response format: { error: 'reference_not_found', ... }
      expect(result.error).toBe('reference_not_found');
    });

    it('should handle different value types (string)', async () => {
      // First create a reference
      const queryRequest = {
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

      const queryResponse = await server['handleRequest'](queryRequest);
      const queryResult = JSON.parse(queryResponse.content[0].text);

      // Set a string property
      const setRequest = {
        method: 'tools/call',
        params: {
          name: 'iac_mcp_set_property',
          arguments: {
            reference: queryResult.reference.id,
            property: 'name',
            value: 'New Window Name'
          }
        }
      };

      const response = await server['handleRequest'](setRequest);

      expect(response.content).toBeDefined();
      expect(response.content).toHaveLength(1);
      expect(response.content[0].type).toBe('text');
    });

    it('should handle different value types (number)', async () => {
      // First create a reference
      const queryRequest = {
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

      const queryResponse = await server['handleRequest'](queryRequest);
      const queryResult = JSON.parse(queryResponse.content[0].text);

      // Set a number property
      const setRequest = {
        method: 'tools/call',
        params: {
          name: 'iac_mcp_set_property',
          arguments: {
            reference: queryResult.reference.id,
            property: 'index',
            value: 42
          }
        }
      };

      const response = await server['handleRequest'](setRequest);

      expect(response.content).toBeDefined();
      expect(response.content).toHaveLength(1);
      expect(response.content[0].type).toBe('text');
    });

    it('should handle null value for clearing properties', async () => {
      // First create a reference
      const queryRequest = {
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

      const queryResponse = await server['handleRequest'](queryRequest);
      const queryResult = JSON.parse(queryResponse.content[0].text);

      // Set a null value
      const setRequest = {
        method: 'tools/call',
        params: {
          name: 'iac_mcp_set_property',
          arguments: {
            reference: queryResult.reference.id,
            property: 'comment',
            value: null
          }
        }
      };

      const response = await server['handleRequest'](setRequest);

      expect(response.content).toBeDefined();
      expect(response.content).toHaveLength(1);
      expect(response.content[0].type).toBe('text');
    });
  });

  describe('CallTool Integration - iac_mcp_get_elements', () => {
    it('should handle iac_mcp_get_elements with reference ID', async () => {
      // First create a mailbox reference
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

      // Now get messages from mailbox
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

    it('should handle iac_mcp_get_elements with specifier', async () => {
      const request = {
        method: 'tools/call',
        params: {
          name: 'iac_mcp_get_elements',
          arguments: {
            container: {
              type: 'named',
              element: 'mailbox',
              name: 'inbox',
              container: 'application'
            },
            elementType: 'message',
            app: 'Mail',  // Required when container is a specifier
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
          name: 'iac_mcp_get_elements',
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

      const result = JSON.parse(response.content[0].text);
      // Error response format: { error: 'reference_not_found', ... }
      expect(result.error).toBe('reference_not_found');
    });
  });

  describe('Error Handling', () => {
    it('should return properly formatted error for missing app parameter', async () => {
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
          name: 'iac_mcp_query_object',
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
