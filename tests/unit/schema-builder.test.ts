import { describe, it, expect, beforeEach } from 'vitest';
import { SchemaBuilder } from '../../src/jitd/tool-generator/schema-builder.js';
import { TypeMapper } from '../../src/jitd/tool-generator/type-mapper.js';
import type { SDEFCommand, SDEFParameter } from '../../src/types/sdef.js';

describe('SchemaBuilder', () => {
  let builder: SchemaBuilder;
  let typeMapper: TypeMapper;

  beforeEach(() => {
    typeMapper = new TypeMapper();
    builder = new SchemaBuilder(typeMapper);
  });

  describe('buildInputSchema - commands with no parameters', () => {
    it('should build schema for command with no parameters', () => {
      const command: SDEFCommand = {
        name: 'quit',
        code: 'aevtquit',
        parameters: [],
      };

      const schema = builder.buildInputSchema(command);

      expect(schema.type).toBe('object');
      expect(schema.properties).toEqual({});
      expect(schema.required).toBeUndefined();
    });

    it('should build schema for command with empty parameters array and no direct parameter', () => {
      const command: SDEFCommand = {
        name: 'activate',
        code: 'miscactv',
        description: 'Activate the application',
        parameters: [],
      };

      const schema = builder.buildInputSchema(command);

      expect(schema.type).toBe('object');
      expect(schema.properties).toEqual({});
      expect(schema.required).toBeUndefined();
    });
  });

  describe('buildInputSchema - commands with only direct parameter', () => {
    it('should build schema for command with required direct parameter', () => {
      const command: SDEFCommand = {
        name: 'open',
        code: 'aevtodoc',
        parameters: [],
        directParameter: {
          name: 'direct-parameter',
          code: '----',
          type: { kind: 'file' },
          description: 'the file to open',
          optional: false,
        },
      };

      const schema = builder.buildInputSchema(command);

      expect(schema.type).toBe('object');
      expect(schema.properties.target).toBeDefined();
      expect(schema.properties.target.type).toBe('string');
      expect(schema.properties.target.description).toContain('file');
      expect(schema.required).toEqual(['target']);
    });

    it('should build schema for command with optional direct parameter', () => {
      const command: SDEFCommand = {
        name: 'print',
        code: 'aevtpdoc',
        parameters: [],
        directParameter: {
          name: 'direct-parameter',
          code: '----',
          type: { kind: 'file' },
          description: 'the file to print',
          optional: true,
        },
      };

      const schema = builder.buildInputSchema(command);

      expect(schema.type).toBe('object');
      expect(schema.properties.target).toBeDefined();
      expect(schema.required).toBeUndefined();
    });

    it('should map direct parameter type correctly using TypeMapper', () => {
      const command: SDEFCommand = {
        name: 'open',
        code: 'aevtodoc',
        parameters: [],
        directParameter: {
          name: 'direct-parameter',
          code: '----',
          type: { kind: 'primitive', type: 'text' },
          description: 'the text to open',
          optional: false,
        },
      };

      const schema = builder.buildInputSchema(command);

      expect(schema.properties.target.type).toBe('string');
    });
  });

  describe('buildInputSchema - commands with only named parameters', () => {
    it('should build schema for command with single required named parameter', () => {
      const command: SDEFCommand = {
        name: 'move',
        code: 'coremove',
        parameters: [
          {
            name: 'to',
            code: 'kfil',
            type: { kind: 'file' },
            description: 'the destination folder',
            optional: false,
          },
        ],
      };

      const schema = builder.buildInputSchema(command);

      expect(schema.type).toBe('object');
      expect(schema.properties.to).toBeDefined();
      expect(schema.properties.to.type).toBe('string');
      expect(schema.properties.to.description).toContain('destination folder');
      expect(schema.required).toEqual(['to']);
    });

    it('should build schema for command with multiple named parameters', () => {
      const command: SDEFCommand = {
        name: 'duplicate',
        code: 'coreclon',
        parameters: [
          {
            name: 'to',
            code: 'kfil',
            type: { kind: 'file' },
            description: 'the destination',
            optional: false,
          },
          {
            name: 'replacing',
            code: 'alrp',
            type: { kind: 'primitive', type: 'boolean' },
            description: 'replace existing files',
            optional: true,
          },
        ],
      };

      const schema = builder.buildInputSchema(command);

      expect(schema.type).toBe('object');
      expect(schema.properties.to).toBeDefined();
      expect(schema.properties.replacing).toBeDefined();
      expect(schema.required).toEqual(['to']);
    });

    it('should build schema for command with all optional named parameters', () => {
      const command: SDEFCommand = {
        name: 'save',
        code: 'coresave',
        parameters: [
          {
            name: 'in',
            code: 'kfil',
            type: { kind: 'file' },
            description: 'the file to save to',
            optional: true,
          },
          {
            name: 'as',
            code: 'fltp',
            type: { kind: 'primitive', type: 'text' },
            description: 'the file format',
            optional: true,
          },
        ],
      };

      const schema = builder.buildInputSchema(command);

      expect(schema.type).toBe('object');
      expect(schema.properties.in).toBeDefined();
      expect(schema.properties.as).toBeDefined();
      expect(schema.required).toBeUndefined();
    });
  });

  describe('buildInputSchema - commands with both direct and named parameters', () => {
    it('should build schema combining direct parameter and named parameters', () => {
      const command: SDEFCommand = {
        name: 'open',
        code: 'aevtodoc',
        parameters: [
          {
            name: 'using',
            code: 'usin',
            type: { kind: 'primitive', type: 'text' },
            description: 'the application to open with',
            optional: true,
          },
        ],
        directParameter: {
          name: 'direct-parameter',
          code: '----',
          type: { kind: 'file' },
          description: 'the file to open',
          optional: false,
        },
      };

      const schema = builder.buildInputSchema(command);

      expect(schema.type).toBe('object');
      expect(schema.properties.target).toBeDefined();
      expect(schema.properties.using).toBeDefined();
      expect(schema.required).toEqual(['target']);
    });

    it('should build schema with multiple required parameters from both direct and named', () => {
      const command: SDEFCommand = {
        name: 'copy',
        code: 'corecopy',
        parameters: [
          {
            name: 'to',
            code: 'kfil',
            type: { kind: 'file' },
            description: 'destination folder',
            optional: false,
          },
          {
            name: 'replacing',
            code: 'alrp',
            type: { kind: 'primitive', type: 'boolean' },
            description: 'replace existing',
            optional: true,
          },
        ],
        directParameter: {
          name: 'direct-parameter',
          code: '----',
          type: { kind: 'file' },
          description: 'the file to copy',
          optional: false,
        },
      };

      const schema = builder.buildInputSchema(command);

      expect(schema.type).toBe('object');
      expect(Object.keys(schema.properties)).toHaveLength(3);
      expect(schema.required).toContain('target');
      expect(schema.required).toContain('to');
      expect(schema.required).not.toContain('replacing');
    });
  });

  describe('parameter descriptions', () => {
    it('should use SDEF description when available', () => {
      const command: SDEFCommand = {
        name: 'open',
        code: 'aevtodoc',
        parameters: [
          {
            name: 'using',
            code: 'usin',
            type: { kind: 'primitive', type: 'text' },
            description: 'the application to open with',
            optional: true,
          },
        ],
      };

      const schema = builder.buildInputSchema(command);

      expect(schema.properties.using.description).toBe('the application to open with');
    });

    it('should generate fallback description when SDEF description is missing', () => {
      const command: SDEFCommand = {
        name: 'move',
        code: 'coremove',
        parameters: [
          {
            name: 'to',
            code: 'kfil',
            type: { kind: 'file' },
            optional: false,
          },
        ],
      };

      const schema = builder.buildInputSchema(command);

      expect(schema.properties.to.description).toBeDefined();
      expect(schema.properties.to.description).toMatch(/to/);
      expect(schema.properties.to.description).toMatch(/move/);
    });

    it('should include type information in description', () => {
      const command: SDEFCommand = {
        name: 'open',
        code: 'aevtodoc',
        parameters: [],
        directParameter: {
          name: 'direct-parameter',
          code: '----',
          type: { kind: 'file' },
          description: 'the file to open',
          optional: false,
        },
      };

      const schema = builder.buildInputSchema(command);

      expect(schema.properties.target.description).toMatch(/file/i);
    });

    it('should handle parameters with very long descriptions', () => {
      const longDescription = 'A'.repeat(500);
      const command: SDEFCommand = {
        name: 'test',
        code: 'testtest',
        parameters: [
          {
            name: 'param',
            code: 'prm1',
            type: { kind: 'primitive', type: 'text' },
            description: longDescription,
            optional: false,
          },
        ],
      };

      const schema = builder.buildInputSchema(command);

      expect(schema.properties.param.description).toBe(longDescription);
    });
  });

  describe('complex parameter types', () => {
    it('should map list types correctly', () => {
      const command: SDEFCommand = {
        name: 'process',
        code: 'testproc',
        parameters: [
          {
            name: 'items',
            code: 'itms',
            type: {
              kind: 'list',
              itemType: { kind: 'primitive', type: 'text' },
            },
            description: 'list of items to process',
            optional: false,
          },
        ],
      };

      const schema = builder.buildInputSchema(command);

      expect(schema.properties.items.type).toBe('array');
      expect(schema.properties.items.items).toBeDefined();
    });

    it('should map record types correctly', () => {
      const command: SDEFCommand = {
        name: 'configure',
        code: 'testconf',
        parameters: [
          {
            name: 'options',
            code: 'opts',
            type: {
              kind: 'record',
              properties: {
                width: { kind: 'primitive', type: 'integer' },
                height: { kind: 'primitive', type: 'integer' },
              },
            },
            description: 'configuration options',
            optional: false,
          },
        ],
      };

      const schema = builder.buildInputSchema(command);

      expect(schema.properties.options.type).toBe('object');
      expect(schema.properties.options.properties).toBeDefined();
    });

    it('should map file types with path description', () => {
      const command: SDEFCommand = {
        name: 'open',
        code: 'aevtodoc',
        parameters: [],
        directParameter: {
          name: 'direct-parameter',
          code: '----',
          type: { kind: 'file' },
          description: 'the file to open',
          optional: false,
        },
      };

      const schema = builder.buildInputSchema(command);

      expect(schema.properties.target.type).toBe('string');
      expect(schema.properties.target.description).toMatch(/file|path/i);
    });

    it('should map all primitive types correctly', () => {
      const command: SDEFCommand = {
        name: 'test',
        code: 'testtest',
        parameters: [
          {
            name: 'text_param',
            code: 'txt1',
            type: { kind: 'primitive', type: 'text' },
            optional: false,
          },
          {
            name: 'int_param',
            code: 'int1',
            type: { kind: 'primitive', type: 'integer' },
            optional: false,
          },
          {
            name: 'real_param',
            code: 'rel1',
            type: { kind: 'primitive', type: 'real' },
            optional: false,
          },
          {
            name: 'bool_param',
            code: 'bol1',
            type: { kind: 'primitive', type: 'boolean' },
            optional: false,
          },
        ],
      };

      const schema = builder.buildInputSchema(command);

      expect(schema.properties.text_param.type).toBe('string');
      expect(schema.properties.int_param.type).toBe('number');
      expect(schema.properties.real_param.type).toBe('number');
      expect(schema.properties.bool_param.type).toBe('boolean');
    });
  });

  describe('real-world Finder command examples', () => {
    it('should build schema for Finder open command', () => {
      const command: SDEFCommand = {
        name: 'open',
        code: 'aevtodoc',
        description: 'Open the specified object(s)',
        parameters: [
          {
            name: 'using',
            code: 'usin',
            type: { kind: 'primitive', type: 'text' },
            description: 'the application to open with',
            optional: true,
          },
        ],
        directParameter: {
          name: 'direct-parameter',
          code: '----',
          type: { kind: 'file' },
          description: 'the file to open',
          optional: false,
        },
        result: { kind: 'primitive', type: 'boolean' },
      };

      const schema = builder.buildInputSchema(command);

      expect(schema.type).toBe('object');
      expect(schema.properties.target).toBeDefined();
      expect(schema.properties.target.type).toBe('string');
      expect(schema.properties.using).toBeDefined();
      expect(schema.properties.using.type).toBe('string');
      expect(schema.required).toEqual(['target']);
    });

    it('should build schema for Finder duplicate command', () => {
      const command: SDEFCommand = {
        name: 'duplicate',
        code: 'coreclon',
        description: 'Duplicate one or more object(s)',
        parameters: [
          {
            name: 'to',
            code: 'kfil',
            type: { kind: 'file' },
            description: 'the location for the new object(s)',
            optional: true,
          },
          {
            name: 'replacing',
            code: 'alrp',
            type: { kind: 'primitive', type: 'boolean' },
            description: 'replace existing files?',
            optional: true,
          },
          {
            name: 'routing suppressed',
            code: 'rout',
            type: { kind: 'primitive', type: 'boolean' },
            description: 'route to destination without user interaction',
            optional: true,
          },
        ],
        directParameter: {
          name: 'direct-parameter',
          code: '----',
          type: { kind: 'file' },
          description: 'the object(s) to duplicate',
          optional: false,
        },
      };

      const schema = builder.buildInputSchema(command);

      expect(schema.type).toBe('object');
      expect(Object.keys(schema.properties)).toHaveLength(4);
      expect(schema.properties.target).toBeDefined();
      expect(schema.properties.to).toBeDefined();
      expect(schema.properties.replacing).toBeDefined();
      expect(schema.properties['routing suppressed']).toBeDefined();
      expect(schema.required).toEqual(['target']);
    });

    it('should build schema for Finder quit command', () => {
      const command: SDEFCommand = {
        name: 'quit',
        code: 'aevtquit',
        description: 'Quit Finder',
        parameters: [],
      };

      const schema = builder.buildInputSchema(command);

      expect(schema.type).toBe('object');
      expect(schema.properties).toEqual({});
      expect(schema.required).toBeUndefined();
    });
  });

  describe('schema validation', () => {
    it('should always have root type as object', () => {
      const commands: SDEFCommand[] = [
        { name: 'quit', code: 'aevtquit', parameters: [] },
        {
          name: 'open',
          code: 'aevtodoc',
          parameters: [],
          directParameter: {
            name: 'direct-parameter',
            code: '----',
            type: { kind: 'file' },
            optional: false,
          },
        },
        {
          name: 'move',
          code: 'coremove',
          parameters: [
            {
              name: 'to',
              code: 'kfil',
              type: { kind: 'file' },
              optional: false,
            },
          ],
        },
      ];

      commands.forEach((command) => {
        const schema = builder.buildInputSchema(command);
        expect(schema.type).toBe('object');
      });
    });

    it('should always have properties as an object', () => {
      const command: SDEFCommand = {
        name: 'quit',
        code: 'aevtquit',
        parameters: [],
      };

      const schema = builder.buildInputSchema(command);

      expect(typeof schema.properties).toBe('object');
      expect(Array.isArray(schema.properties)).toBe(false);
    });

    it('should have required as array or undefined, not empty array', () => {
      const commandWithRequired: SDEFCommand = {
        name: 'open',
        code: 'aevtodoc',
        parameters: [],
        directParameter: {
          name: 'direct-parameter',
          code: '----',
          type: { kind: 'file' },
          optional: false,
        },
      };

      const commandWithoutRequired: SDEFCommand = {
        name: 'quit',
        code: 'aevtquit',
        parameters: [],
      };

      const schemaWithRequired = builder.buildInputSchema(commandWithRequired);
      const schemaWithoutRequired = builder.buildInputSchema(commandWithoutRequired);

      expect(Array.isArray(schemaWithRequired.required)).toBe(true);
      expect(schemaWithRequired.required!.length).toBeGreaterThan(0);
      expect(schemaWithoutRequired.required).toBeUndefined();
    });

    it('should have all property values as valid JSON Schema', () => {
      const command: SDEFCommand = {
        name: 'test',
        code: 'testtest',
        parameters: [
          {
            name: 'param1',
            code: 'prm1',
            type: { kind: 'primitive', type: 'text' },
            description: 'test parameter',
            optional: false,
          },
        ],
      };

      const schema = builder.buildInputSchema(command);

      Object.values(schema.properties).forEach((property) => {
        expect(property.type).toBeDefined();
        expect(property.type).not.toBe(null);
        expect(property.type).not.toBe(undefined);
      });
    });

    it('should not have null or undefined values in schema properties', () => {
      const command: SDEFCommand = {
        name: 'test',
        code: 'testtest',
        parameters: [
          {
            name: 'param1',
            code: 'prm1',
            type: { kind: 'primitive', type: 'text' },
            optional: false,
          },
        ],
      };

      const schema = builder.buildInputSchema(command);

      const schemaJson = JSON.stringify(schema);
      expect(schemaJson).not.toContain('null');
      expect(schemaJson).not.toContain('undefined');
    });
  });

  describe('edge cases', () => {
    it('should handle command with 10+ parameters', () => {
      const parameters = Array.from({ length: 12 }, (_, i) => ({
        name: `param${i + 1}`,
        code: `pr${String(i + 1).padStart(2, '0')}`,
        type: { kind: 'primitive', type: 'text' } as const,
        description: `parameter ${i + 1}`,
        optional: i % 2 === 0,
      }));

      const command: SDEFCommand = {
        name: 'complex',
        code: 'testcplx',
        parameters,
      };

      const schema = builder.buildInputSchema(command);

      expect(Object.keys(schema.properties)).toHaveLength(12);
      expect(schema.required?.length).toBe(6); // Half are required (odd indices)
    });

    it('should handle parameters with special characters in names', () => {
      const command: SDEFCommand = {
        name: 'test',
        code: 'testtest',
        parameters: [
          {
            name: 'routing suppressed',
            code: 'rout',
            type: { kind: 'primitive', type: 'boolean' },
            description: 'suppress routing',
            optional: false,
          },
          {
            name: 'with-dashes',
            code: 'dash',
            type: { kind: 'primitive', type: 'text' },
            description: 'param with dashes',
            optional: false,
          },
        ],
      };

      const schema = builder.buildInputSchema(command);

      expect(schema.properties['routing suppressed']).toBeDefined();
      expect(schema.properties['with-dashes']).toBeDefined();
      expect(schema.required).toContain('routing suppressed');
      expect(schema.required).toContain('with-dashes');
    });

    it('should handle parameters with empty string descriptions', () => {
      const command: SDEFCommand = {
        name: 'test',
        code: 'testtest',
        parameters: [
          {
            name: 'param1',
            code: 'prm1',
            type: { kind: 'primitive', type: 'text' },
            description: '',
            optional: false,
          },
        ],
      };

      const schema = builder.buildInputSchema(command);

      expect(schema.properties.param1.description).toBeDefined();
      expect(schema.properties.param1.description.length).toBeGreaterThan(0);
    });

    it('should handle commands with only optional parameters', () => {
      const command: SDEFCommand = {
        name: 'configure',
        code: 'testconf',
        parameters: [
          {
            name: 'option1',
            code: 'opt1',
            type: { kind: 'primitive', type: 'text' },
            optional: true,
          },
          {
            name: 'option2',
            code: 'opt2',
            type: { kind: 'primitive', type: 'boolean' },
            optional: true,
          },
          {
            name: 'option3',
            code: 'opt3',
            type: { kind: 'primitive', type: 'integer' },
            optional: true,
          },
        ],
      };

      const schema = builder.buildInputSchema(command);

      expect(Object.keys(schema.properties)).toHaveLength(3);
      expect(schema.required).toBeUndefined();
    });

    it('should handle nested list types', () => {
      const command: SDEFCommand = {
        name: 'process',
        code: 'testproc',
        parameters: [
          {
            name: 'matrix',
            code: 'mtrx',
            type: {
              kind: 'list',
              itemType: {
                kind: 'list',
                itemType: { kind: 'primitive', type: 'integer' },
              },
            },
            description: 'nested list of integers',
            optional: false,
          },
        ],
      };

      const schema = builder.buildInputSchema(command);

      expect(schema.properties.matrix.type).toBe('array');
      expect(schema.properties.matrix.items).toBeDefined();
    });
  });
});
