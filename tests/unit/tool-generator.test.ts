import { describe, it, expect, beforeEach, vi } from 'vitest';
import type { SDEFCommand, SDEFDictionary, SDEFSuite, SDEFType } from '../../src/types/sdef.js';
import { ToolGenerator, type AppInfo, type ToolGeneratorOptions } from '../../src/jitd/tool-generator/generator.js';
import type { MCPTool } from '../../src/types/mcp-tool.js';

/**
 * Comprehensive test suite for ToolGenerator
 *
 * The ToolGenerator is the main orchestration class that combines:
 * - TypeMapper: SDEF types → JSON Schema types
 * - NamingUtility: Command names → MCP tool names
 * - SchemaBuilder: Parameters → JSON Schema input schemas
 *
 * It generates complete MCP tools from SDEF data at three levels:
 * 1. Single command → single tool
 * 2. Suite → multiple tools
 * 3. Full dictionary → all tools
 *
 * It also implements caching to avoid regenerating tools for the same app.
 */

describe('ToolGenerator', () => {
  let generator: ToolGenerator;
  let defaultAppInfo: AppInfo;

  beforeEach(() => {
    generator = new ToolGenerator();
    defaultAppInfo = {
      appName: 'Finder',
      bundleId: 'com.apple.finder',
      bundlePath: '/System/Library/CoreServices/Finder.app',
      sdefPath: '/System/Library/CoreServices/Finder.app/Contents/Resources/Finder.sdef',
    };
  });

  describe('generateTool - single command to single tool', () => {
    it('should generate valid MCP tool from simple command with no parameters', () => {
      const command: SDEFCommand = {
        name: 'quit',
        code: 'aevtquit',
        description: 'Quit the application',
        parameters: [],
      };

      const tool = generator.generateTool(command, defaultAppInfo);

      expect(tool.name).toBe('finder_quit');
      expect(tool.description).toBe('Quit the application');
      expect(tool.inputSchema.type).toBe('object');
      expect(tool.inputSchema.properties).toEqual({});
      expect(tool.inputSchema.required).toEqual([]);
    });

    it('should generate tool from command with direct parameter', () => {
      const command: SDEFCommand = {
        name: 'open',
        code: 'aevtodoc',
        description: 'Open the specified object(s)',
        parameters: [],
        directParameter: {
          name: 'direct-parameter',
          code: '----',
          type: { kind: 'file' },
          description: 'the file to open',
          optional: false,
        },
      };

      const tool = generator.generateTool(command, defaultAppInfo);

      expect(tool.name).toBe('finder_open');
      expect(tool.description).toBe('Open the specified object(s)');
      expect(tool.inputSchema.type).toBe('object');
      expect(tool.inputSchema.properties.target).toBeDefined();
      expect(tool.inputSchema.properties.target.type).toBe('string');
      expect(tool.inputSchema.properties.target.description).toBe('the file to open');
      expect(tool.inputSchema.required).toContain('target');
    });

    it('should generate tool from command with named parameters', () => {
      const command: SDEFCommand = {
        name: 'duplicate',
        code: 'coreclon',
        description: 'Duplicate one or more objects',
        parameters: [
          {
            name: 'to',
            code: 'insh',
            type: { kind: 'file' },
            description: 'the location for the new copy',
            optional: true,
          },
          {
            name: 'replacing',
            code: 'alrp',
            type: { kind: 'primitive', type: 'boolean' },
            description: 'replace existing files?',
            optional: true,
          },
        ],
        directParameter: {
          name: 'direct-parameter',
          code: '----',
          type: { kind: 'file' },
          description: 'the item to duplicate',
          optional: false,
        },
      };

      const tool = generator.generateTool(command, defaultAppInfo);

      expect(tool.name).toBe('finder_duplicate');
      expect(tool.description).toBe('Duplicate one or more objects');
      expect(tool.inputSchema.type).toBe('object');
      expect(tool.inputSchema.properties.target).toBeDefined();
      expect(tool.inputSchema.properties.to).toBeDefined();
      expect(tool.inputSchema.properties.replacing).toBeDefined();
      expect(tool.inputSchema.required).toEqual(['target']);
    });

    it('should generate tool with description from command', () => {
      const command: SDEFCommand = {
        name: 'eject',
        code: 'fndrejct',
        description: 'Eject the specified disk(s)',
        parameters: [],
        directParameter: {
          name: 'direct-parameter',
          code: '----',
          type: { kind: 'file' },
          description: 'the disk to eject',
          optional: false,
        },
      };

      const tool = generator.generateTool(command, defaultAppInfo);

      expect(tool.description).toBe('Eject the specified disk(s)');
    });

    it('should generate description for command without description', () => {
      const command: SDEFCommand = {
        name: 'custom action',
        code: 'custactn',
        parameters: [],
      };

      const tool = generator.generateTool(command, defaultAppInfo);

      expect(tool.description).toBeTruthy();
      expect(tool.description.length).toBeGreaterThan(0);
      // Should generate something like "Execute custom action command"
      expect(tool.description.toLowerCase()).toContain('custom action');
    });

    it('should include metadata for execution layer', () => {
      const command: SDEFCommand = {
        name: 'open',
        code: 'aevtodoc',
        description: 'Open the specified object(s)',
        parameters: [],
        directParameter: {
          name: 'direct-parameter',
          code: '----',
          type: { kind: 'file' },
          description: 'the file to open',
          optional: false,
        },
        result: { kind: 'primitive', type: 'boolean' },
      };

      const tool = generator.generateTool(command, defaultAppInfo, 'Standard Suite');

      expect(tool._metadata).toBeDefined();
      expect(tool._metadata?.appName).toBe('Finder');
      expect(tool._metadata?.bundleId).toBe('com.apple.finder');
      expect(tool._metadata?.commandName).toBe('open');
      expect(tool._metadata?.commandCode).toBe('aevtodoc');
      expect(tool._metadata?.suiteName).toBe('Standard Suite');
      expect(tool._metadata?.directParameterName).toBe('target');
      expect(tool._metadata?.resultType).toEqual({ kind: 'primitive', type: 'boolean' });
    });

    it('should handle command with optional direct parameter', () => {
      const command: SDEFCommand = {
        name: 'activate',
        code: 'miscactv',
        description: 'Make the application active',
        parameters: [],
        directParameter: {
          name: 'direct-parameter',
          code: '----',
          type: { kind: 'primitive', type: 'text' },
          description: 'optional window name',
          optional: true,
        },
      };

      const tool = generator.generateTool(command, defaultAppInfo);

      expect(tool.inputSchema.required).toEqual([]);
      expect(tool.inputSchema.properties.target).toBeDefined();
    });

    it('should handle command with 10+ parameters', () => {
      const command: SDEFCommand = {
        name: 'complex command',
        code: 'cmplxcmd',
        description: 'A command with many parameters',
        parameters: Array.from({ length: 10 }, (_, i) => ({
          name: `param${i + 1}`,
          code: `prm${i + 1}`,
          type: { kind: 'primitive', type: 'text' } as SDEFType,
          description: `Parameter ${i + 1}`,
          optional: i > 4, // First 5 required, rest optional
        })),
      };

      const tool = generator.generateTool(command, defaultAppInfo);

      expect(Object.keys(tool.inputSchema.properties)).toHaveLength(10);
      expect(tool.inputSchema.required).toHaveLength(5);
    });

    it('should handle command with very long description', () => {
      const longDescription = 'A'.repeat(600);
      const command: SDEFCommand = {
        name: 'verbose',
        code: 'verbcmnd',
        description: longDescription,
        parameters: [],
      };

      const tool = generator.generateTool(command, defaultAppInfo);

      expect(tool.description).toBeTruthy();
      // Default max length might truncate or handle long descriptions
      expect(tool.description.length).toBeGreaterThan(0);
    });
  });

  describe('generateToolsForSuite - suite to multiple tools', () => {
    it('should generate tools for suite with 3 commands', () => {
      const suite: SDEFSuite = {
        name: 'Standard Suite',
        code: 'core',
        description: 'Common commands for all applications',
        commands: [
          {
            name: 'quit',
            code: 'aevtquit',
            description: 'Quit the application',
            parameters: [],
          },
          {
            name: 'open',
            code: 'aevtodoc',
            description: 'Open a document',
            parameters: [],
            directParameter: {
              name: 'direct-parameter',
              code: '----',
              type: { kind: 'file' },
              description: 'the document to open',
              optional: false,
            },
          },
          {
            name: 'close',
            code: 'coreclos',
            description: 'Close a window',
            parameters: [],
          },
        ],
        classes: [],
        enumerations: [],
      };

      const tools = generator.generateToolsForSuite(suite, defaultAppInfo);

      expect(tools).toHaveLength(3);
      expect(tools[0].name).toBe('finder_quit');
      expect(tools[1].name).toBe('finder_open');
      expect(tools[2].name).toBe('finder_close');
    });

    it('should generate empty array for suite with no commands', () => {
      const suite: SDEFSuite = {
        name: 'Empty Suite',
        code: 'empt',
        commands: [],
        classes: [],
        enumerations: [],
      };

      const tools = generator.generateToolsForSuite(suite, defaultAppInfo);

      expect(tools).toEqual([]);
    });

    it('should include suite name in tool metadata', () => {
      const suite: SDEFSuite = {
        name: 'Finder Suite',
        code: 'fndr',
        commands: [
          {
            name: 'eject',
            code: 'fndrejct',
            description: 'Eject a disk',
            parameters: [],
          },
        ],
        classes: [],
        enumerations: [],
      };

      const tools = generator.generateToolsForSuite(suite, defaultAppInfo);

      expect(tools[0]._metadata?.suiteName).toBe('Finder Suite');
    });

    it('should handle suite with commands that have same name prefix', () => {
      const suite: SDEFSuite = {
        name: 'Test Suite',
        code: 'test',
        commands: [
          {
            name: 'open',
            code: 'openone',
            description: 'Open one item',
            parameters: [],
          },
          {
            name: 'open selection',
            code: 'opensel',
            description: 'Open selection',
            parameters: [],
          },
          {
            name: 'open with',
            code: 'openwth',
            description: 'Open with application',
            parameters: [],
          },
        ],
        classes: [],
        enumerations: [],
      };

      const tools = generator.generateToolsForSuite(suite, defaultAppInfo);

      expect(tools).toHaveLength(3);
      // All names should be unique
      const names = tools.map(t => t.name);
      expect(new Set(names).size).toBe(3);
    });
  });

  describe('generateTools - full dictionary to all tools', () => {
    it('should generate tools from dictionary with 2 suites and 5 commands total', () => {
      const dictionary: SDEFDictionary = {
        title: 'Test Application Dictionary',
        suites: [
          {
            name: 'Standard Suite',
            code: 'core',
            commands: [
              {
                name: 'quit',
                code: 'aevtquit',
                description: 'Quit the application',
                parameters: [],
              },
              {
                name: 'open',
                code: 'aevtodoc',
                description: 'Open a document',
                parameters: [],
              },
              {
                name: 'close',
                code: 'coreclos',
                description: 'Close a window',
                parameters: [],
              },
            ],
            classes: [],
            enumerations: [],
          },
          {
            name: 'Custom Suite',
            code: 'cust',
            commands: [
              {
                name: 'custom action',
                code: 'custactn',
                description: 'Perform custom action',
                parameters: [],
              },
              {
                name: 'special command',
                code: 'splcmnd',
                description: 'Execute special command',
                parameters: [],
              },
            ],
            classes: [],
            enumerations: [],
          },
        ],
      };

      const tools = generator.generateTools(dictionary, defaultAppInfo);

      expect(tools).toHaveLength(5);
      expect(tools[0].name).toBe('finder_quit');
      expect(tools[1].name).toBe('finder_open');
      expect(tools[2].name).toBe('finder_close');
      expect(tools[3].name).toBe('finder_custom_action');
      expect(tools[4].name).toBe('finder_special_command');
    });

    it('should generate tools from dictionary with nested structures', () => {
      const dictionary: SDEFDictionary = {
        title: 'Complex Dictionary',
        suites: [
          {
            name: 'Suite A',
            code: 'suta',
            commands: [
              {
                name: 'cmd1',
                code: 'cmd1code',
                parameters: [
                  {
                    name: 'nested',
                    code: 'nest',
                    type: {
                      kind: 'list',
                      itemType: {
                        kind: 'record',
                        properties: {
                          name: { kind: 'primitive', type: 'text' },
                          count: { kind: 'primitive', type: 'integer' },
                        },
                      },
                    },
                    description: 'nested parameter',
                    optional: false,
                  },
                ],
              },
            ],
            classes: [],
            enumerations: [],
          },
        ],
      };

      const tools = generator.generateTools(dictionary, defaultAppInfo);

      expect(tools).toHaveLength(1);
      expect(tools[0].inputSchema.properties.nested).toBeDefined();
      expect(tools[0].inputSchema.properties.nested.type).toBe('array');
    });

    it('should ensure all tool names are unique across entire dictionary', () => {
      const dictionary: SDEFDictionary = {
        title: 'Dictionary with Potential Collisions',
        suites: [
          {
            name: 'Suite A',
            code: 'suta',
            commands: [
              {
                name: 'open',
                code: 'openone',
                description: 'Open from Suite A',
                parameters: [],
              },
            ],
            classes: [],
            enumerations: [],
          },
          {
            name: 'Suite B',
            code: 'sutb',
            commands: [
              {
                name: 'open',
                code: 'opentwo',
                description: 'Open from Suite B',
                parameters: [],
              },
            ],
            classes: [],
            enumerations: [],
          },
          {
            name: 'Suite C',
            code: 'sutc',
            commands: [
              {
                name: 'open',
                code: 'openthr',
                description: 'Open from Suite C',
                parameters: [],
              },
            ],
            classes: [],
            enumerations: [],
          },
        ],
      };

      const tools = generator.generateTools(dictionary, defaultAppInfo);

      expect(tools).toHaveLength(3);

      const names = tools.map(t => t.name);
      const uniqueNames = new Set(names);
      expect(uniqueNames.size).toBe(3); // All names must be unique
    });

    it('should handle empty dictionary', () => {
      const dictionary: SDEFDictionary = {
        title: 'Empty Dictionary',
        suites: [],
      };

      const tools = generator.generateTools(dictionary, defaultAppInfo);

      expect(tools).toEqual([]);
    });

    it('should handle dictionary with empty suites', () => {
      const dictionary: SDEFDictionary = {
        title: 'Dictionary with Empty Suites',
        suites: [
          {
            name: 'Empty Suite 1',
            code: 'emp1',
            commands: [],
            classes: [],
            enumerations: [],
          },
          {
            name: 'Empty Suite 2',
            code: 'emp2',
            commands: [],
            classes: [],
            enumerations: [],
          },
        ],
      };

      const tools = generator.generateTools(dictionary, defaultAppInfo);

      expect(tools).toEqual([]);
    });
  });

  describe('tool structure validation', () => {
    it('should ensure every tool has required fields', () => {
      const command: SDEFCommand = {
        name: 'test',
        code: 'testcode',
        description: 'Test command',
        parameters: [],
      };

      const tool = generator.generateTool(command, defaultAppInfo);

      expect(tool).toHaveProperty('name');
      expect(tool).toHaveProperty('description');
      expect(tool).toHaveProperty('inputSchema');
      expect(typeof tool.name).toBe('string');
      expect(typeof tool.description).toBe('string');
      expect(typeof tool.inputSchema).toBe('object');
    });

    it('should ensure inputSchema always has type object', () => {
      const command: SDEFCommand = {
        name: 'test',
        code: 'testcode',
        parameters: [],
      };

      const tool = generator.generateTool(command, defaultAppInfo);

      expect(tool.inputSchema.type).toBe('object');
    });

    it('should ensure tool name follows naming conventions', () => {
      const command: SDEFCommand = {
        name: 'Test Command',
        code: 'testcmnd',
        parameters: [],
      };

      const tool = generator.generateTool(command, defaultAppInfo);

      // Should be lowercase with underscores
      expect(tool.name).toMatch(/^[a-z]+(_[a-z]+)*$/);
      expect(tool.name).toBe('finder_test_command');
    });

    it('should ensure description is non-empty', () => {
      const command: SDEFCommand = {
        name: 'test',
        code: 'testcode',
        parameters: [],
      };

      const tool = generator.generateTool(command, defaultAppInfo);

      expect(tool.description).toBeTruthy();
      expect(tool.description.length).toBeGreaterThan(0);
    });

    it('should ensure metadata is populated correctly', () => {
      const command: SDEFCommand = {
        name: 'test',
        code: 'testcode',
        description: 'Test command',
        parameters: [],
        result: { kind: 'primitive', type: 'text' },
      };

      const tool = generator.generateTool(command, defaultAppInfo, 'Test Suite');

      expect(tool._metadata).toBeDefined();
      expect(tool._metadata?.appName).toBe(defaultAppInfo.appName);
      expect(tool._metadata?.bundleId).toBe(defaultAppInfo.bundleId);
      expect(tool._metadata?.commandName).toBe('test');
      expect(tool._metadata?.commandCode).toBe('testcode');
      expect(tool._metadata?.suiteName).toBe('Test Suite');
      expect(tool._metadata?.resultType).toEqual({ kind: 'primitive', type: 'text' });
    });
  });

  describe('caching behavior', () => {
    it('should cache generated tools by bundle ID', () => {
      const dictionary: SDEFDictionary = {
        title: 'Test Dictionary',
        suites: [
          {
            name: 'Test Suite',
            code: 'test',
            commands: [
              {
                name: 'test command',
                code: 'testcmnd',
                parameters: [],
              },
            ],
            classes: [],
            enumerations: [],
          },
        ],
      };

      // First call generates
      const tools1 = generator.generateTools(dictionary, defaultAppInfo);

      // Second call returns cached (same reference)
      const tools2 = generator.generateTools(dictionary, defaultAppInfo);

      expect(tools1).toBe(tools2); // Same object reference
    });

    it('should use cache key based on bundle ID', () => {
      const dictionary: SDEFDictionary = {
        title: 'Test Dictionary',
        suites: [
          {
            name: 'Test Suite',
            code: 'test',
            commands: [
              {
                name: 'test',
                code: 'testcmnd',
                parameters: [],
              },
            ],
            classes: [],
            enumerations: [],
          },
        ],
      };

      const appInfo1: AppInfo = {
        appName: 'App1',
        bundleId: 'com.test.app1',
        bundlePath: '/Applications/App1.app',
        sdefPath: '/Applications/App1.app/Contents/Resources/App1.sdef',
      };

      const appInfo2: AppInfo = {
        appName: 'App2',
        bundleId: 'com.test.app2',
        bundlePath: '/Applications/App2.app',
        sdefPath: '/Applications/App2.app/Contents/Resources/App2.sdef',
      };

      const tools1 = generator.generateTools(dictionary, appInfo1);
      const tools2 = generator.generateTools(dictionary, appInfo2);

      // Different bundle IDs should not share cache
      expect(tools1).not.toBe(tools2);
      expect(tools1[0].name).toBe('app1_test');
      expect(tools2[0].name).toBe('app2_test');
    });

    it('should clear cache when clearCache is called', () => {
      const dictionary: SDEFDictionary = {
        title: 'Test Dictionary',
        suites: [
          {
            name: 'Test Suite',
            code: 'test',
            commands: [
              {
                name: 'test',
                code: 'testcmnd',
                parameters: [],
              },
            ],
            classes: [],
            enumerations: [],
          },
        ],
      };

      // Generate and cache
      const tools1 = generator.generateTools(dictionary, defaultAppInfo);

      // Clear cache
      generator.clearCache();

      // Generate again (should be new instance)
      const tools2 = generator.generateTools(dictionary, defaultAppInfo);

      expect(tools1).not.toBe(tools2); // Different object references
      expect(tools1).toEqual(tools2); // But same content
    });

    it('should maintain separate cache entries for different bundle IDs', () => {
      const dictionary: SDEFDictionary = {
        title: 'Test Dictionary',
        suites: [
          {
            name: 'Test Suite',
            code: 'test',
            commands: [
              {
                name: 'test',
                code: 'testcmnd',
                parameters: [],
              },
            ],
            classes: [],
            enumerations: [],
          },
        ],
      };

      const app1: AppInfo = {
        appName: 'App1',
        bundleId: 'com.test.app1',
        bundlePath: '/Applications/App1.app',
        sdefPath: '/Applications/App1.app/Contents/Resources/App1.sdef',
      };

      const app2: AppInfo = {
        appName: 'App2',
        bundleId: 'com.test.app2',
        bundlePath: '/Applications/App2.app',
        sdefPath: '/Applications/App2.app/Contents/Resources/App2.sdef',
      };

      // Generate for both apps
      const tools1a = generator.generateTools(dictionary, app1);
      const tools2a = generator.generateTools(dictionary, app2);

      // Generate again (should use cache)
      const tools1b = generator.generateTools(dictionary, app1);
      const tools2b = generator.generateTools(dictionary, app2);

      expect(tools1a).toBe(tools1b); // App1 cache hit
      expect(tools2a).toBe(tools2b); // App2 cache hit
      expect(tools1a).not.toBe(tools2a); // Different apps
    });

    it('should not cache failed generations', () => {
      const invalidDictionary: SDEFDictionary = {
        title: 'Invalid Dictionary',
        suites: [
          {
            name: 'Test Suite',
            code: 'test',
            commands: [
              {
                name: 'invalid',
                code: '', // Invalid: empty code
                parameters: [],
              },
            ],
            classes: [],
            enumerations: [],
          },
        ],
      };

      // First attempt should fail
      expect(() => {
        generator.generateTools(invalidDictionary, defaultAppInfo);
      }).toThrow();

      // Fix the dictionary
      invalidDictionary.suites[0].commands[0].code = 'validcod';

      // Second attempt should succeed and not use failed cache
      const tools = generator.generateTools(invalidDictionary, defaultAppInfo);
      expect(tools).toHaveLength(1);
    });
  });

  describe('integration with sub-components', () => {
    it('should use TypeMapper for parameter type conversion', () => {
      const command: SDEFCommand = {
        name: 'test',
        code: 'testcode',
        parameters: [
          {
            name: 'text_param',
            code: 'txtp',
            type: { kind: 'primitive', type: 'text' },
            description: 'A text parameter',
            optional: false,
          },
          {
            name: 'number_param',
            code: 'nump',
            type: { kind: 'primitive', type: 'integer' },
            description: 'A number parameter',
            optional: false,
          },
        ],
      };

      const tool = generator.generateTool(command, defaultAppInfo);

      // TypeMapper should convert text → string, integer → number
      expect(tool.inputSchema.properties.text_param.type).toBe('string');
      expect(tool.inputSchema.properties.number_param.type).toBe('number');
    });

    it('should use NamingUtility for tool name generation', () => {
      const command: SDEFCommand = {
        name: 'Complex Command Name',
        code: 'cmplxcmd',
        parameters: [],
      };

      const appInfo: AppInfo = {
        appName: 'MyApp',
        bundleId: 'com.example.myapp',
        bundlePath: '/Applications/MyApp.app',
        sdefPath: '/Applications/MyApp.app/Contents/Resources/MyApp.sdef',
      };

      const tool = generator.generateTool(command, appInfo);

      // NamingUtility should produce: lowercase, underscores, app prefix
      expect(tool.name).toBe('myapp_complex_command_name');
    });

    it('should use SchemaBuilder for input schema construction', () => {
      const command: SDEFCommand = {
        name: 'test',
        code: 'testcode',
        parameters: [
          {
            name: 'required_param',
            code: 'reqp',
            type: { kind: 'primitive', type: 'text' },
            description: 'Required parameter',
            optional: false,
          },
          {
            name: 'optional_param',
            code: 'optp',
            type: { kind: 'primitive', type: 'text' },
            description: 'Optional parameter',
            optional: true,
          },
        ],
      };

      const tool = generator.generateTool(command, defaultAppInfo);

      // SchemaBuilder should construct proper schema with required array
      expect(tool.inputSchema.type).toBe('object');
      expect(tool.inputSchema.properties).toHaveProperty('required_param');
      expect(tool.inputSchema.properties).toHaveProperty('optional_param');
      expect(tool.inputSchema.required).toContain('required_param');
      expect(tool.inputSchema.required).not.toContain('optional_param');
    });

    it('should coordinate all three components correctly', () => {
      const command: SDEFCommand = {
        name: 'move',
        code: 'coremove',
        description: 'Move object(s) to a new location',
        parameters: [
          {
            name: 'to',
            code: 'insh',
            type: { kind: 'file' },
            description: 'the destination',
            optional: false,
          },
        ],
        directParameter: {
          name: 'direct-parameter',
          code: '----',
          type: { kind: 'file' },
          description: 'the object to move',
          optional: false,
        },
      };

      const tool = generator.generateTool(command, defaultAppInfo);

      // NamingUtility: generates name
      expect(tool.name).toBe('finder_move');

      // Description from command
      expect(tool.description).toBe('Move object(s) to a new location');

      // SchemaBuilder: constructs schema
      expect(tool.inputSchema.type).toBe('object');
      expect(tool.inputSchema.properties).toHaveProperty('target');
      expect(tool.inputSchema.properties).toHaveProperty('to');

      // TypeMapper: converts file → string
      expect(tool.inputSchema.properties.target.type).toBe('string');
      expect(tool.inputSchema.properties.to.type).toBe('string');

      // Both required
      expect(tool.inputSchema.required).toEqual(['target', 'to']);
    });
  });

  describe('name collision handling', () => {
    it('should handle commands with same name in different suites', () => {
      const dictionary: SDEFDictionary = {
        title: 'Dictionary with Name Collisions',
        suites: [
          {
            name: 'Suite A',
            code: 'suta',
            commands: [
              {
                name: 'open',
                code: 'opena',
                description: 'Open from Suite A',
                parameters: [],
              },
            ],
            classes: [],
            enumerations: [],
          },
          {
            name: 'Suite B',
            code: 'sutb',
            commands: [
              {
                name: 'open',
                code: 'openb',
                description: 'Open from Suite B',
                parameters: [],
              },
            ],
            classes: [],
            enumerations: [],
          },
        ],
      };

      const tools = generator.generateTools(dictionary, defaultAppInfo);

      expect(tools).toHaveLength(2);

      // NamingUtility should resolve collision
      const names = tools.map(t => t.name);
      expect(new Set(names).size).toBe(2); // Both names unique
    });

    it('should ensure all generated tool names are unique', () => {
      const dictionary: SDEFDictionary = {
        title: 'Large Dictionary',
        suites: [
          {
            name: 'Suite 1',
            code: 'sut1',
            commands: Array.from({ length: 20 }, (_, i) => ({
              name: i % 3 === 0 ? 'duplicate' : `cmd${i}`,
              code: `cmd${i}`,
              parameters: [],
            })),
            classes: [],
            enumerations: [],
          },
        ],
      };

      const tools = generator.generateTools(dictionary, defaultAppInfo);

      const names = tools.map(t => t.name);
      const uniqueNames = new Set(names);

      expect(uniqueNames.size).toBe(tools.length); // All unique
    });
  });

  describe('edge cases', () => {
    it('should handle command with no code attribute', () => {
      const command: SDEFCommand = {
        name: 'invalid',
        code: '', // Empty code
        parameters: [],
      };

      expect(() => {
        generator.generateTool(command, defaultAppInfo);
      }).toThrow();
    });

    it('should handle command with very long parameter list', () => {
      const command: SDEFCommand = {
        name: 'many params',
        code: 'manyprms',
        parameters: Array.from({ length: 15 }, (_, i) => ({
          name: `param_${i}`,
          code: `prm${i}`,
          type: { kind: 'primitive', type: 'text' } as SDEFType,
          description: `Parameter ${i}`,
          optional: i > 7,
        })),
      };

      const tool = generator.generateTool(command, defaultAppInfo);

      expect(Object.keys(tool.inputSchema.properties)).toHaveLength(15);
      expect(tool.inputSchema.required).toHaveLength(8);
    });

    it('should handle command with extremely long description', () => {
      const longDescription = 'A'.repeat(1000);
      const command: SDEFCommand = {
        name: 'verbose',
        code: 'verbcmnd',
        description: longDescription,
        parameters: [],
      };

      // Should not throw
      const tool = generator.generateTool(command, defaultAppInfo);
      expect(tool.description).toBeTruthy();
    });

    it('should handle empty SDEF dictionary gracefully', () => {
      const dictionary: SDEFDictionary = {
        title: 'Empty',
        suites: [],
      };

      const tools = generator.generateTools(dictionary, defaultAppInfo);
      expect(tools).toEqual([]);
    });

    it('should handle suite with only hidden commands when includeHiddenCommands is false', () => {
      // This tests the options parameter - hidden commands filtering
      const generator = new ToolGenerator({ includeHiddenCommands: false });

      const suite: SDEFSuite = {
        name: 'Test Suite',
        code: 'test',
        commands: [
          {
            name: 'visible',
            code: 'visiblcm',
            parameters: [],
          },
          // Assume hidden property exists in extended type
        ],
        classes: [],
        enumerations: [],
      };

      const tools = generator.generateToolsForSuite(suite, defaultAppInfo);
      expect(tools.length).toBeGreaterThan(0);
    });
  });

  describe('real-world example - Finder SDEF', () => {
    it('should generate all Finder tools from real SDEF', async () => {
      // Import parser to load real SDEF
      const { SDEFParser } = await import('../../src/jitd/discovery/parse-sdef.js');
      const parser = new SDEFParser();

      const sdefPath = '/System/Library/CoreServices/Finder.app/Contents/Resources/Finder.sdef';
      const sdefData = await parser.parse(sdefPath);

      const finderAppInfo: AppInfo = {
        appName: 'Finder',
        bundleId: 'com.apple.finder',
        bundlePath: '/System/Library/CoreServices/Finder.app',
        sdefPath,
      };

      const tools = generator.generateTools(sdefData, finderAppInfo);

      // Finder has approximately 25-30 commands across multiple suites
      expect(tools.length).toBeGreaterThan(20);
      expect(tools.length).toBeLessThan(50);

      // All tools should be valid MCP tools
      tools.forEach(tool => {
        expect(tool.name).toBeTruthy();
        expect(tool.description).toBeTruthy();
        expect(tool.inputSchema.type).toBe('object');
      });
    });

    it('should verify specific Finder tools exist', async () => {
      const { SDEFParser } = await import('../../src/jitd/discovery/parse-sdef.js');
      const parser = new SDEFParser();

      const sdefPath = '/System/Library/CoreServices/Finder.app/Contents/Resources/Finder.sdef';
      const sdefData = await parser.parse(sdefPath);

      const finderAppInfo: AppInfo = {
        appName: 'Finder',
        bundleId: 'com.apple.finder',
        bundlePath: '/System/Library/CoreServices/Finder.app',
        sdefPath,
      };

      const tools = generator.generateTools(sdefData, finderAppInfo);

      // Check for common Finder commands
      const openTool = tools.find(t => t.name === 'finder_open');
      const duplicateTool = tools.find(t => t.name === 'finder_duplicate');
      const moveTool = tools.find(t => t.name === 'finder_move');

      expect(openTool).toBeDefined();
      expect(duplicateTool).toBeDefined();
      expect(moveTool).toBeDefined();

      // Verify structure of specific tools
      if (openTool) {
        expect(openTool.inputSchema.type).toBe('object');
        expect(openTool.inputSchema.properties.target).toBeDefined();
      }
    });

    it('should ensure all Finder tools are valid MCP tools', async () => {
      const { SDEFParser } = await import('../../src/jitd/discovery/parse-sdef.js');
      const parser = new SDEFParser();

      const sdefPath = '/System/Library/CoreServices/Finder.app/Contents/Resources/Finder.sdef';
      const sdefData = await parser.parse(sdefPath);

      const finderAppInfo: AppInfo = {
        appName: 'Finder',
        bundleId: 'com.apple.finder',
        bundlePath: '/System/Library/CoreServices/Finder.app',
        sdefPath,
      };

      const tools = generator.generateTools(sdefData, finderAppInfo);

      // Validate every tool structure
      tools.forEach(tool => {
        // Required fields
        expect(tool).toHaveProperty('name');
        expect(tool).toHaveProperty('description');
        expect(tool).toHaveProperty('inputSchema');

        // Valid types
        expect(typeof tool.name).toBe('string');
        expect(typeof tool.description).toBe('string');
        expect(typeof tool.inputSchema).toBe('object');

        // Schema structure
        expect(tool.inputSchema.type).toBe('object');
        expect(tool.inputSchema.properties).toBeDefined();
        expect(Array.isArray(tool.inputSchema.required)).toBe(true);

        // Metadata
        expect(tool._metadata).toBeDefined();
        expect(tool._metadata?.appName).toBe('Finder');
        expect(tool._metadata?.bundleId).toBe('com.apple.finder');
      });
    });
  });

  describe('options parameter', () => {
    it('should respect namingStrategy option', () => {
      const generatorWithPrefix = new ToolGenerator({ namingStrategy: 'suite_prefix' });

      const command: SDEFCommand = {
        name: 'test',
        code: 'testcode',
        parameters: [],
      };

      const tool = generatorWithPrefix.generateTool(command, defaultAppInfo, 'Custom Suite');

      // Exact behavior depends on NamingUtility implementation
      expect(tool.name).toBeTruthy();
    });

    it('should respect maxDescriptionLength option', () => {
      const generatorWithLimit = new ToolGenerator({ maxDescriptionLength: 50 });

      const command: SDEFCommand = {
        name: 'test',
        code: 'testcode',
        description: 'A'.repeat(200),
        parameters: [],
      };

      const tool = generatorWithLimit.generateTool(command, defaultAppInfo);

      expect(tool.description.length).toBeLessThanOrEqual(50);
    });

    it('should respect strictValidation option', () => {
      const generatorStrict = new ToolGenerator({ strictValidation: true });

      const invalidCommand: SDEFCommand = {
        name: '', // Invalid: empty name
        code: 'testcode',
        parameters: [],
      };

      expect(() => {
        generatorStrict.generateTool(invalidCommand, defaultAppInfo);
      }).toThrow();
    });
  });
});
