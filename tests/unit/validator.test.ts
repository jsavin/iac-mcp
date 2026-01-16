import { describe, it, expect, beforeEach } from 'vitest';
import { ToolValidator } from '../../src/jitd/tool-generator/validator.js';
import type { JSONSchemaProperty } from '../../src/jitd/tool-generator/type-mapper.js';

/**
 * Tests for MCP Tool Validator
 *
 * The ToolValidator ensures all generated tools comply with MCP protocol requirements
 * and catches any malformed tool definitions before they are exposed to LLMs.
 *
 * Validation rules:
 * 1. Name: non-empty, alphanumeric + underscores, max 64 chars
 * 2. Description: non-empty, max 500 chars
 * 3. inputSchema: must have type: "object"
 * 4. Properties: all must have valid JSON Schema types
 * 5. Required: must be subset of properties
 * 6. No circular references in schema
 * 7. Schema must be JSON-serializable
 */

/**
 * MCPTool type definition (minimal version for testing)
 * This represents a tool definition compliant with MCP protocol
 */
export interface MCPTool {
  name: string;
  description: string;
  inputSchema: JSONSchema;
}

/**
 * JSON Schema definition for tool input schemas
 */
export interface JSONSchema {
  type: 'object';
  properties?: Record<string, JSONSchemaProperty>;
  required?: string[];
}

describe('ToolValidator', () => {
  let validator: ToolValidator;

  beforeEach(() => {
    validator = new ToolValidator();
  });

  describe('validate - valid tools', () => {
    it('should pass validation for simple valid tool', () => {
      const tool: MCPTool = {
        name: 'finder_open',
        description: 'Open the specified object(s)',
        inputSchema: {
          type: 'object',
          properties: {
            target: {
              type: 'string',
              description: 'File path to open',
            },
          },
          required: ['target'],
        },
      };

      const result = validator.validate(tool);

      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should pass validation for tool with complex schema', () => {
      const tool: MCPTool = {
        name: 'finder_duplicate',
        description: 'Duplicate files or folders',
        inputSchema: {
          type: 'object',
          properties: {
            items: {
              type: 'array',
              items: { type: 'string' },
              description: 'List of file paths to duplicate',
            },
            to: {
              type: 'string',
              description: 'Destination folder',
            },
            replacing: {
              type: 'boolean',
              description: 'Replace existing files',
            },
          },
          required: ['items'],
        },
      };

      const result = validator.validate(tool);

      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should pass validation for tool with optional parameters', () => {
      const tool: MCPTool = {
        name: 'finder_move',
        description: 'Move items to a new location',
        inputSchema: {
          type: 'object',
          properties: {
            items: {
              type: 'array',
              items: { type: 'string' },
              description: 'Items to move',
            },
            to: {
              type: 'string',
              description: 'Destination',
            },
          },
          required: ['items', 'to'],
        },
      };

      const result = validator.validate(tool);

      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should pass validation for tool with arrays and objects', () => {
      const tool: MCPTool = {
        name: 'test_complex',
        description: 'Test tool with complex types',
        inputSchema: {
          type: 'object',
          properties: {
            arrayProp: {
              type: 'array',
              items: { type: 'number' },
            },
            objectProp: {
              type: 'object',
              properties: {
                nested: { type: 'string' },
              },
            },
          },
        },
      };

      const result = validator.validate(tool);

      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should pass validation for tool with enumerations', () => {
      const tool: MCPTool = {
        name: 'finder_set_view',
        description: 'Set the view mode',
        inputSchema: {
          type: 'object',
          properties: {
            mode: {
              type: 'string',
              enum: ['icon', 'list', 'column', 'cover-flow'],
              description: 'View mode',
            },
          },
          required: ['mode'],
        },
      };

      const result = validator.validate(tool);

      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should pass validation for tool with empty properties object', () => {
      const tool: MCPTool = {
        name: 'finder_quit',
        description: 'Quit the Finder application',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      };

      const result = validator.validate(tool);

      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should pass validation for tool with no required array', () => {
      const tool: MCPTool = {
        name: 'test_tool',
        description: 'Test tool with all optional parameters',
        inputSchema: {
          type: 'object',
          properties: {
            optional1: { type: 'string' },
            optional2: { type: 'number' },
          },
        },
      };

      const result = validator.validate(tool);

      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });
  });

  describe('validateName', () => {
    it('should accept valid alphanumeric name with underscores', () => {
      const errors = validator.validateName('finder_open_file');
      expect(errors).toHaveLength(0);
    });

    it('should accept name with numbers', () => {
      const errors = validator.validateName('tool_v2_open');
      expect(errors).toHaveLength(0);
    });

    it('should reject empty name', () => {
      const errors = validator.validateName('');
      expect(errors.length).toBeGreaterThan(0);
      expect(errors[0].field).toBe('name');
      expect(errors[0].message).toContain('empty');
      expect(errors[0].severity).toBe('error');
    });

    it('should reject name with spaces', () => {
      const errors = validator.validateName('finder open');
      expect(errors.length).toBeGreaterThan(0);
      expect(errors[0].field).toBe('name');
      expect(errors[0].message.toLowerCase()).toMatch(/alphanumeric|underscore/);
      expect(errors[0].severity).toBe('error');
    });

    it('should reject name with special characters', () => {
      const errors = validator.validateName('finder-open-file');
      expect(errors.length).toBeGreaterThan(0);
      expect(errors[0].field).toBe('name');
      expect(errors[0].message.toLowerCase()).toMatch(/alphanumeric|underscore/);
    });

    it('should reject name with hyphens', () => {
      const errors = validator.validateName('finder-open');
      expect(errors.length).toBeGreaterThan(0);
    });

    it('should reject name with dots', () => {
      const errors = validator.validateName('finder.open');
      expect(errors.length).toBeGreaterThan(0);
    });

    it('should reject name longer than 64 characters', () => {
      const longName = 'a'.repeat(65);
      const errors = validator.validateName(longName);
      expect(errors.length).toBeGreaterThan(0);
      expect(errors[0].field).toBe('name');
      expect(errors[0].message).toContain('64');
      expect(errors[0].severity).toBe('error');
    });

    it('should accept name with exactly 64 characters', () => {
      const maxName = 'a'.repeat(64);
      const errors = validator.validateName(maxName);
      expect(errors).toHaveLength(0);
    });

    it('should reject name starting with underscore', () => {
      const errors = validator.validateName('_finder_open');
      expect(errors.length).toBeGreaterThan(0);
      expect(errors[0].message.toLowerCase()).toContain('start');
    });

    it('should reject name starting with number', () => {
      const errors = validator.validateName('1finder_open');
      expect(errors.length).toBeGreaterThan(0);
      expect(errors[0].message.toLowerCase()).toContain('start');
    });
  });

  describe('validateDescription', () => {
    it('should accept valid description', () => {
      const errors = validator.validateDescription('Open the specified file or folder');
      expect(errors).toHaveLength(0);
    });

    it('should accept description with special characters', () => {
      const errors = validator.validateDescription('Open file(s) & folder(s)');
      expect(errors).toHaveLength(0);
    });

    it('should reject empty description', () => {
      const errors = validator.validateDescription('');
      expect(errors.length).toBeGreaterThan(0);
      expect(errors[0].field).toBe('description');
      expect(errors[0].message).toContain('empty');
      expect(errors[0].severity).toBe('error');
    });

    it('should reject description with only whitespace', () => {
      const errors = validator.validateDescription('   ');
      expect(errors.length).toBeGreaterThan(0);
      expect(errors[0].field).toBe('description');
      expect(errors[0].message.toLowerCase()).toMatch(/empty|whitespace/);
    });

    it('should warn for description longer than 500 characters', () => {
      const longDesc = 'a'.repeat(501);
      const result = validator.validateDescription(longDesc);
      // This should be a warning, not an error
      expect(result).toHaveLength(0); // No errors
    });

    it('should accept description with exactly 500 characters', () => {
      const maxDesc = 'a'.repeat(500);
      const errors = validator.validateDescription(maxDesc);
      expect(errors).toHaveLength(0);
    });
  });

  describe('validateSchema', () => {
    it('should validate schema with correct type', () => {
      const schema: JSONSchema = {
        type: 'object',
        properties: {
          foo: { type: 'string' },
        },
      };

      const result = validator.validateSchema(schema);

      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should fail validation for missing type', () => {
      const schema = {
        properties: {
          foo: { type: 'string' },
        },
      } as any;

      const result = validator.validateSchema(schema);

      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.field === 'inputSchema.type')).toBe(true);
    });

    it('should fail validation for incorrect type', () => {
      const schema = {
        type: 'string',
        properties: {},
      } as any;

      const result = validator.validateSchema(schema);

      expect(result.valid).toBe(false);
      expect(result.errors.some(e =>
        e.field === 'inputSchema.type' &&
        e.message.toLowerCase().includes('object')
      )).toBe(true);
    });

    it('should fail validation when properties is not an object', () => {
      const schema = {
        type: 'object',
        properties: 'invalid',
      } as any;

      const result = validator.validateSchema(schema);

      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.field === 'inputSchema.properties')).toBe(true);
    });

    it('should fail validation for property with invalid type', () => {
      const schema: JSONSchema = {
        type: 'object',
        properties: {
          foo: { type: 'invalid' } as any,
        },
      };

      const result = validator.validateSchema(schema);

      expect(result.valid).toBe(false);
      expect(result.errors.some(e =>
        e.field.includes('foo') &&
        e.message.toLowerCase().includes('type')
      )).toBe(true);
    });

    it('should validate required fields are subset of properties', () => {
      const schema: JSONSchema = {
        type: 'object',
        properties: {
          foo: { type: 'string' },
        },
        required: ['foo', 'bar'], // 'bar' not in properties
      };

      const result = validator.validateSchema(schema);

      expect(result.valid).toBe(false);
      expect(result.errors.some(e =>
        e.message.includes('bar') ||
        e.message.toLowerCase().includes('required')
      )).toBe(true);
    });

    it('should fail validation when required is not an array', () => {
      const schema = {
        type: 'object',
        properties: {
          foo: { type: 'string' },
        },
        required: 'foo',
      } as any;

      const result = validator.validateSchema(schema);

      expect(result.valid).toBe(false);
      expect(result.errors.some(e =>
        e.field === 'inputSchema.required' &&
        e.message.toLowerCase().includes('array')
      )).toBe(true);
    });

    it('should warn for duplicate values in required array', () => {
      const schema: JSONSchema = {
        type: 'object',
        properties: {
          foo: { type: 'string' },
        },
        required: ['foo', 'foo'],
      };

      const result = validator.validateSchema(schema);

      // Should be valid but with warnings
      expect(result.valid).toBe(true);
      expect(result.warnings.some(w =>
        w.message.toLowerCase().includes('duplicate')
      )).toBe(true);
    });

    it('should detect circular references in schema', () => {
      const circular: any = {
        type: 'object',
        properties: {
          self: { type: 'object', properties: {} },
        },
      };
      // Create circular reference
      circular.properties.self.properties.circular = circular;

      const result = validator.validateSchema(circular);

      expect(result.valid).toBe(false);
      expect(result.errors.some(e =>
        e.message.toLowerCase().includes('circular')
      )).toBe(true);
    });

    it('should fail validation for schema with function values', () => {
      const schema = {
        type: 'object',
        properties: {
          foo: {
            type: 'string',
            validator: () => true, // Functions not serializable
          },
        },
      } as any;

      const result = validator.validateSchema(schema);

      expect(result.valid).toBe(false);
      expect(result.errors.some(e =>
        e.message.toLowerCase().includes('serializable') ||
        e.message.toLowerCase().includes('function')
      )).toBe(true);
    });

    it('should fail validation for schema with undefined values', () => {
      const schema = {
        type: 'object',
        properties: {
          foo: {
            type: 'string',
            description: undefined,
          },
        },
      } as any;

      const result = validator.validateSchema(schema);

      expect(result.valid).toBe(false);
      expect(result.errors.some(e =>
        e.message.toLowerCase().includes('serializable') ||
        e.message.toLowerCase().includes('undefined')
      )).toBe(true);
    });

    it('should pass validation for valid schema that serializes correctly', () => {
      const schema: JSONSchema = {
        type: 'object',
        properties: {
          foo: { type: 'string' },
          bar: { type: 'number' },
        },
        required: ['foo'],
      };

      const result = validator.validateSchema(schema);

      expect(result.valid).toBe(true);
      // Should be able to serialize
      expect(() => JSON.stringify(schema)).not.toThrow();
    });

    it('should validate deeply nested schema', () => {
      const schema: JSONSchema = {
        type: 'object',
        properties: {
          level1: {
            type: 'object',
            properties: {
              level2: {
                type: 'object',
                properties: {
                  level3: { type: 'string' },
                },
              },
            },
          },
        },
      };

      const result = validator.validateSchema(schema);

      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should validate schema with 50+ properties', () => {
      const properties: Record<string, JSONSchemaProperty> = {};
      for (let i = 0; i < 50; i++) {
        properties[`prop${i}`] = { type: 'string' };
      }

      const schema: JSONSchema = {
        type: 'object',
        properties,
      };

      const result = validator.validateSchema(schema);

      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });
  });

  describe('validate - invalid tools (integration)', () => {
    it('should fail validation for tool with empty name', () => {
      const tool: MCPTool = {
        name: '',
        description: 'Test tool',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      };

      const result = validator.validate(tool);

      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.field === 'name')).toBe(true);
    });

    it('should fail validation for tool with invalid schema type', () => {
      const tool: MCPTool = {
        name: 'test_tool',
        description: 'Test tool',
        inputSchema: {
          type: 'string' as any,
          properties: {},
        },
      };

      const result = validator.validate(tool);

      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.field === 'inputSchema.type')).toBe(true);
    });

    it('should fail validation for tool with missing description', () => {
      const tool = {
        name: 'test_tool',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      } as any;

      const result = validator.validate(tool);

      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.field === 'description')).toBe(true);
    });

    it('should return multiple errors for tool with multiple issues', () => {
      const tool: MCPTool = {
        name: 'invalid name!',
        description: '',
        inputSchema: {
          type: 'string' as any,
          properties: {},
          required: ['nonexistent'],
        },
      };

      const result = validator.validate(tool);

      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(1);

      // Should have errors for name, description, and schema
      expect(result.errors.some(e => e.field === 'name')).toBe(true);
      expect(result.errors.some(e => e.field === 'description')).toBe(true);
      expect(result.errors.some(e => e.field.includes('inputSchema'))).toBe(true);
    });

    it('should separate errors and warnings correctly', () => {
      const tool: MCPTool = {
        name: 'valid_tool',
        description: 'Valid description',
        inputSchema: {
          type: 'object',
          properties: {
            foo: { type: 'string' },
          },
          required: ['foo', 'foo'], // Duplicate in required (warning)
        },
      };

      const result = validator.validate(tool);

      expect(result.valid).toBe(true); // No errors, just warnings
      expect(result.errors).toHaveLength(0);
      expect(result.warnings.length).toBeGreaterThan(0);
      expect(result.warnings[0].severity).toBe('warning');
    });
  });

  describe('edge cases', () => {
    it('should handle tool with null values gracefully', () => {
      const tool = {
        name: 'test_tool',
        description: null,
        inputSchema: {
          type: 'object',
          properties: {},
        },
      } as any;

      const result = validator.validate(tool);

      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.field === 'description')).toBe(true);
    });

    it('should handle tool with missing inputSchema', () => {
      const tool = {
        name: 'test_tool',
        description: 'Test tool',
      } as any;

      const result = validator.validate(tool);

      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.field === 'inputSchema')).toBe(true);
    });

    it('should validate schema with array items of complex type', () => {
      const schema: JSONSchema = {
        type: 'object',
        properties: {
          items: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                name: { type: 'string' },
                value: { type: 'number' },
              },
            },
          },
        },
      };

      const result = validator.validateSchema(schema);

      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should handle schema with Symbol values', () => {
      const schema = {
        type: 'object',
        properties: {
          foo: {
            type: 'string',
            [Symbol('test')]: 'value',
          },
        },
      } as any;

      const result = validator.validateSchema(schema);

      // Symbols are not JSON-serializable
      expect(result.valid).toBe(false);
      expect(result.errors.some(e =>
        e.message.toLowerCase().includes('serializable')
      )).toBe(true);
    });
  });
});
