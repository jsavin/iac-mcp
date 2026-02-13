/**
 * Integration Tests for Large Value Handling in MCP
 *
 * Tests the MCP server integration for:
 * - get_cached_value tool appears in ListTools
 * - tail_lines/head_lines params in property tool schemas
 * - CallTool routes correctly for get_cached_value
 * - Mutual exclusivity validation for tail_lines/head_lines
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { IACMCPServer } from '../../src/mcp/server.js';
import type { MCPTool } from '../../src/types/mcp-tool.js';

describe('Large Value Handling MCP Integration', () => {
  let server: IACMCPServer;

  beforeEach(async () => {
    server = new IACMCPServer({ enableLogging: false, disableJxaExecution: true });
    await server.initialize();
    await server.start();
  });

  afterEach(async () => {
    await server.stop();
  });

  describe('ListTools Integration', () => {
    it('should include get_cached_value in ListTools response', async () => {
      const response = await server['handleRequest']({
        method: 'tools/list',
        params: {},
      });
      const tools = response.tools as MCPTool[];
      const tool = tools.find(t => t.name === 'iac_mcp_get_cached_value');

      expect(tool).toBeDefined();
      expect(tool!.description).toContain('cached large property value');
      expect(tool!.inputSchema.required).toContain('ref');
    });

    it('should have tail_lines/head_lines in get_cached_value schema', async () => {
      const response = await server['handleRequest']({
        method: 'tools/list',
        params: {},
      });
      const tools = response.tools as MCPTool[];
      const tool = tools.find(t => t.name === 'iac_mcp_get_cached_value');

      const props = tool!.inputSchema.properties as Record<string, any>;
      expect(props.ref).toBeDefined();
      expect(props.tail_lines).toBeDefined();
      expect(props.head_lines).toBeDefined();
      expect(props.offset_lines).toBeDefined();
      expect(props.max_lines).toBeDefined();
    });

    it('should have tail_lines/head_lines in get_properties schema', async () => {
      const response = await server['handleRequest']({
        method: 'tools/list',
        params: {},
      });
      const tools = response.tools as MCPTool[];
      const tool = tools.find(t => t.name === 'iac_mcp_get_properties');

      const props = tool!.inputSchema.properties as Record<string, any>;
      expect(props.tail_lines).toBeDefined();
      expect(props.head_lines).toBeDefined();
    });

    it('should have tail_lines/head_lines in get_elements_with_properties schema', async () => {
      const response = await server['handleRequest']({
        method: 'tools/list',
        params: {},
      });
      const tools = response.tools as MCPTool[];
      const tool = tools.find(t => t.name === 'iac_mcp_get_elements_with_properties');

      const props = tool!.inputSchema.properties as Record<string, any>;
      expect(props.tail_lines).toBeDefined();
      expect(props.head_lines).toBeDefined();
    });

    it('should have tail_lines/head_lines in get_properties_batch schema', async () => {
      const response = await server['handleRequest']({
        method: 'tools/list',
        params: {},
      });
      const tools = response.tools as MCPTool[];
      const tool = tools.find(t => t.name === 'iac_mcp_get_properties_batch');

      const props = tool!.inputSchema.properties as Record<string, any>;
      expect(props.tail_lines).toBeDefined();
      expect(props.head_lines).toBeDefined();
    });
  });

  describe('CallTool - get_cached_value', () => {
    it('should return cache_miss error for non-existent ref', async () => {
      const response = await server['handleRequest']({
        method: 'tools/call',
        params: {
          name: 'iac_mcp_get_cached_value',
          arguments: { ref: 'cache_nonexistent' },
        },
      }) as { content: Array<{ type: string; text: string }>; isError?: boolean };

      expect(response.isError).toBe(true);
      const body = JSON.parse(response.content[0]!.text);
      expect(body.error).toBe('cache_miss');
    });

    it('should return error for invalid params (missing ref)', async () => {
      const response = await server['handleRequest']({
        method: 'tools/call',
        params: {
          name: 'iac_mcp_get_cached_value',
          arguments: {},
        },
      }) as { content: Array<{ type: string; text: string }>; isError?: boolean };

      expect(response.isError).toBe(true);
      const body = JSON.parse(response.content[0]!.text);
      expect(body.error).toBe('invalid_parameter');
    });
  });

  describe('Mutual Exclusivity Validation', () => {
    it('should reject both tail_lines and head_lines on get_properties', async () => {
      const response = await server['handleRequest']({
        method: 'tools/call',
        params: {
          name: 'iac_mcp_get_properties',
          arguments: { reference: 'ref_dummy', tail_lines: 10, head_lines: 10 },
        },
      }) as { content: Array<{ type: string; text: string }>; isError?: boolean };

      expect(response.isError).toBe(true);
      const body = JSON.parse(response.content[0]!.text);
      expect(body.message).toContain('Cannot specify both');
    });

    it('should reject both tail_lines and head_lines on get_cached_value', async () => {
      const response = await server['handleRequest']({
        method: 'tools/call',
        params: {
          name: 'iac_mcp_get_cached_value',
          arguments: { ref: 'cache_123', tail_lines: 5, head_lines: 5 },
        },
      }) as { content: Array<{ type: string; text: string }>; isError?: boolean };

      expect(response.isError).toBe(true);
      const body = JSON.parse(response.content[0]!.text);
      expect(body.message).toContain('Cannot specify both');
    });

    it('should reject both tail_lines and head_lines on get_properties_batch', async () => {
      const response = await server['handleRequest']({
        method: 'tools/call',
        params: {
          name: 'iac_mcp_get_properties_batch',
          arguments: { references: [], tail_lines: 5, head_lines: 5 },
        },
      }) as { content: Array<{ type: string; text: string }>; isError?: boolean };

      expect(response.isError).toBe(true);
      const body = JSON.parse(response.content[0]!.text);
      expect(body.message).toContain('Cannot specify both');
    });

    it('should reject both tail_lines and head_lines on get_elements_with_properties', async () => {
      const response = await server['handleRequest']({
        method: 'tools/call',
        params: {
          name: 'iac_mcp_get_elements_with_properties',
          arguments: {
            container: { type: 'element', element: 'window', index: 0, container: 'application' },
            elementType: 'tab',
            properties: ['name'],
            app: 'Safari',
            tail_lines: 5,
            head_lines: 5,
          },
        },
      }) as { content: Array<{ type: string; text: string }>; isError?: boolean };

      expect(response.isError).toBe(true);
      const body = JSON.parse(response.content[0]!.text);
      expect(body.message).toContain('Cannot specify both');
    });
  });
});
