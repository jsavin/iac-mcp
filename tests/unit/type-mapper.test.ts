import { describe, it, expect, beforeEach } from 'vitest';
import type { SDEFType, SDEFEnumeration } from '../../src/types/sdef.js';
import { TypeMapper, type JSONSchemaProperty } from '../../src/jitd/tool-generator/type-mapper.js';

/**
 * Tests for SDEF Type → JSON Schema Type Mapper
 *
 * The TypeMapper converts SDEF type definitions from parsed SDEF files
 * into JSON Schema properties for MCP tool input schemas.
 *
 * This is a critical component for generating valid MCP tools that can
 * be understood and called by LLMs like Claude.
 */

describe('TypeMapper', () => {
  let mapper: TypeMapper;

  beforeEach(() => {
    mapper = new TypeMapper();
  });

  describe('primitive types', () => {
    it('should map text type to JSON Schema string', () => {
      const sdefType: SDEFType = { kind: 'primitive', type: 'text' };
      const result = mapper.mapType(sdefType);

      expect(result).toEqual({ type: 'string' });
    });

    it('should map integer type to JSON Schema number', () => {
      const sdefType: SDEFType = { kind: 'primitive', type: 'integer' };
      const result = mapper.mapType(sdefType);

      expect(result).toEqual({ type: 'number' });
    });

    it('should map real type to JSON Schema number', () => {
      const sdefType: SDEFType = { kind: 'primitive', type: 'real' };
      const result = mapper.mapType(sdefType);

      expect(result).toEqual({ type: 'number' });
    });

    it('should map boolean type to JSON Schema boolean', () => {
      const sdefType: SDEFType = { kind: 'primitive', type: 'boolean' };
      const result = mapper.mapType(sdefType);

      expect(result).toEqual({ type: 'boolean' });
    });
  });

  describe('file types', () => {
    it('should map file type to string with file path description', () => {
      const sdefType: SDEFType = { kind: 'file' };
      const result = mapper.mapType(sdefType);

      expect(result).toEqual({
        type: 'string',
        description: 'File path',
      });
    });
  });

  describe('list types', () => {
    it('should map generic list to array type', () => {
      const sdefType: SDEFType = {
        kind: 'list',
        itemType: { kind: 'primitive', type: 'text' },
      };
      const result = mapper.mapType(sdefType);

      expect(result.type).toBe('array');
      expect(result.items).toBeDefined();
    });

    it('should map list of text to array of strings', () => {
      const sdefType: SDEFType = {
        kind: 'list',
        itemType: { kind: 'primitive', type: 'text' },
      };
      const result = mapper.mapType(sdefType);

      expect(result).toEqual({
        type: 'array',
        items: { type: 'string' },
      });
    });

    it('should map list of integers to array of numbers', () => {
      const sdefType: SDEFType = {
        kind: 'list',
        itemType: { kind: 'primitive', type: 'integer' },
      };
      const result = mapper.mapType(sdefType);

      expect(result).toEqual({
        type: 'array',
        items: { type: 'number' },
      });
    });

    it('should map list of files to array of strings with file path description', () => {
      const sdefType: SDEFType = {
        kind: 'list',
        itemType: { kind: 'file' },
      };
      const result = mapper.mapType(sdefType);

      expect(result).toEqual({
        type: 'array',
        items: {
          type: 'string',
          description: 'File path',
        },
      });
    });

    it('should map list of records to array of objects', () => {
      const sdefType: SDEFType = {
        kind: 'list',
        itemType: {
          kind: 'record',
          properties: {
            name: { kind: 'primitive', type: 'text' },
            age: { kind: 'primitive', type: 'integer' },
          },
        },
      };
      const result = mapper.mapType(sdefType);

      expect(result.type).toBe('array');
      expect(result.items).toBeDefined();
      expect(result.items?.type).toBe('object');
      expect(result.items?.properties).toBeDefined();
      expect(result.items?.properties?.name).toEqual({ type: 'string' });
      expect(result.items?.properties?.age).toEqual({ type: 'number' });
    });

    it('should map nested lists (list of list of text)', () => {
      const sdefType: SDEFType = {
        kind: 'list',
        itemType: {
          kind: 'list',
          itemType: { kind: 'primitive', type: 'text' },
        },
      };
      const result = mapper.mapType(sdefType);

      expect(result).toEqual({
        type: 'array',
        items: {
          type: 'array',
          items: { type: 'string' },
        },
      });
    });

    it('should map list of class references to array of objects', () => {
      const sdefType: SDEFType = {
        kind: 'list',
        itemType: { kind: 'class', className: 'window' },
      };
      const result = mapper.mapType(sdefType);

      expect(result.type).toBe('array');
      expect(result.items?.type).toBe('object');
      expect(result.items?.description).toContain('window');
    });
  });

  describe('record types', () => {
    it('should map simple record with primitive properties', () => {
      const sdefType: SDEFType = {
        kind: 'record',
        properties: {
          name: { kind: 'primitive', type: 'text' },
          count: { kind: 'primitive', type: 'integer' },
        },
      };
      const result = mapper.mapType(sdefType);

      expect(result).toEqual({
        type: 'object',
        properties: {
          name: { type: 'string' },
          count: { type: 'number' },
        },
      });
    });

    it('should map record with mixed property types', () => {
      const sdefType: SDEFType = {
        kind: 'record',
        properties: {
          title: { kind: 'primitive', type: 'text' },
          visible: { kind: 'primitive', type: 'boolean' },
          position: { kind: 'primitive', type: 'integer' },
          path: { kind: 'file' },
        },
      };
      const result = mapper.mapType(sdefType);

      expect(result.type).toBe('object');
      expect(result.properties).toEqual({
        title: { type: 'string' },
        visible: { type: 'boolean' },
        position: { type: 'number' },
        path: { type: 'string', description: 'File path' },
      });
    });

    it('should map nested records', () => {
      const sdefType: SDEFType = {
        kind: 'record',
        properties: {
          user: {
            kind: 'record',
            properties: {
              name: { kind: 'primitive', type: 'text' },
              age: { kind: 'primitive', type: 'integer' },
            },
          },
          active: { kind: 'primitive', type: 'boolean' },
        },
      };
      const result = mapper.mapType(sdefType);

      expect(result.type).toBe('object');
      expect(result.properties?.user).toEqual({
        type: 'object',
        properties: {
          name: { type: 'string' },
          age: { type: 'number' },
        },
      });
      expect(result.properties?.active).toEqual({ type: 'boolean' });
    });

    it('should map record with list properties', () => {
      const sdefType: SDEFType = {
        kind: 'record',
        properties: {
          tags: {
            kind: 'list',
            itemType: { kind: 'primitive', type: 'text' },
          },
          files: {
            kind: 'list',
            itemType: { kind: 'file' },
          },
        },
      };
      const result = mapper.mapType(sdefType);

      expect(result.type).toBe('object');
      expect(result.properties?.tags).toEqual({
        type: 'array',
        items: { type: 'string' },
      });
      expect(result.properties?.files).toEqual({
        type: 'array',
        items: { type: 'string', description: 'File path' },
      });
    });

    it('should map empty record', () => {
      const sdefType: SDEFType = {
        kind: 'record',
        properties: {},
      };
      const result = mapper.mapType(sdefType);

      expect(result).toEqual({
        type: 'object',
        properties: {},
      });
    });
  });

  describe('class references', () => {
    it('should map class reference to object with descriptive message', () => {
      const sdefType: SDEFType = {
        kind: 'class',
        className: 'window',
      };
      const result = mapper.mapType(sdefType);

      expect(result.type).toBe('object');
      expect(result.description).toBeDefined();
      expect(result.description).toContain('window');
    });

    it('should map class reference with camelCase name', () => {
      const sdefType: SDEFType = {
        kind: 'class',
        className: 'finderWindow',
      };
      const result = mapper.mapType(sdefType);

      expect(result.type).toBe('object');
      expect(result.description).toContain('finderWindow');
    });

    it('should map class reference with spaces in name', () => {
      const sdefType: SDEFType = {
        kind: 'class',
        className: 'Finder window',
      };
      const result = mapper.mapType(sdefType);

      expect(result.type).toBe('object');
      expect(result.description).toContain('Finder window');
    });
  });

  describe('enumerations', () => {
    it('should map enumeration to string with enum constraint', () => {
      const enumeration: SDEFEnumeration = {
        name: 'save options',
        code: 'savo',
        enumerators: [
          { name: 'yes', code: 'yes ' },
          { name: 'no', code: 'no  ' },
          { name: 'ask', code: 'ask ' },
        ],
      };

      const sdefType: SDEFType = {
        kind: 'enumeration',
        enumerationName: 'save options',
      };

      const result = mapper.mapType(sdefType, enumeration);

      expect(result).toEqual({
        type: 'string',
        enum: ['yes', 'no', 'ask'],
      });
    });

    it('should map enumeration with single value', () => {
      const enumeration: SDEFEnumeration = {
        name: 'single option',
        code: 'sngl',
        enumerators: [{ name: 'only', code: 'only' }],
      };

      const sdefType: SDEFType = {
        kind: 'enumeration',
        enumerationName: 'single option',
      };

      const result = mapper.mapType(sdefType, enumeration);

      expect(result).toEqual({
        type: 'string',
        enum: ['only'],
      });
    });

    it('should handle enumeration without enumerators data', () => {
      const sdefType: SDEFType = {
        kind: 'enumeration',
        enumerationName: 'unknown enum',
      };

      const result = mapper.mapType(sdefType);

      expect(result.type).toBe('string');
      expect(result.description).toBeDefined();
      expect(result.description).toContain('unknown enum');
    });

    it('should map enumeration with long names', () => {
      const enumeration: SDEFEnumeration = {
        name: 'view options',
        code: 'view',
        enumerators: [
          { name: 'icon view', code: 'icnv' },
          { name: 'list view', code: 'lstv' },
          { name: 'column view', code: 'clmv' },
          { name: 'flow view', code: 'flwv' },
        ],
      };

      const sdefType: SDEFType = {
        kind: 'enumeration',
        enumerationName: 'view options',
      };

      const result = mapper.mapType(sdefType, enumeration);

      expect(result.type).toBe('string');
      expect(result.enum).toEqual(['icon view', 'list view', 'column view', 'flow view']);
    });
  });

  describe('edge cases and error handling', () => {
    it('should handle undefined type gracefully', () => {
      // @ts-expect-error Testing runtime behavior with invalid input
      const result = mapper.mapType(undefined);

      expect(result.type).toBe('string');
      expect(result.description).toBeDefined();
    });

    it('should handle null type gracefully', () => {
      // @ts-expect-error Testing runtime behavior with invalid input
      const result = mapper.mapType(null);

      expect(result.type).toBe('string');
      expect(result.description).toBeDefined();
    });

    it('should handle unknown type kind with fallback to string', () => {
      const sdefType = { kind: 'unknown-type' } as unknown as SDEFType;
      const result = mapper.mapType(sdefType);

      expect(result.type).toBe('string');
      expect(result.description).toBeDefined();
    });

    it('should handle deeply nested complex types', () => {
      const sdefType: SDEFType = {
        kind: 'list',
        itemType: {
          kind: 'record',
          properties: {
            items: {
              kind: 'list',
              itemType: {
                kind: 'record',
                properties: {
                  value: { kind: 'primitive', type: 'text' },
                  count: { kind: 'primitive', type: 'integer' },
                },
              },
            },
          },
        },
      };

      const result = mapper.mapType(sdefType);

      expect(result.type).toBe('array');
      expect(result.items?.type).toBe('object');
      expect(result.items?.properties?.items?.type).toBe('array');
      expect(result.items?.properties?.items?.items?.type).toBe('object');
    });

    it('should handle list with undefined itemType', () => {
      // @ts-expect-error Testing runtime behavior with invalid input
      const sdefType: SDEFType = { kind: 'list', itemType: undefined };
      const result = mapper.mapType(sdefType);

      expect(result.type).toBe('array');
      expect(result.items).toBeDefined();
    });

    it('should handle record with undefined properties', () => {
      // @ts-expect-error Testing runtime behavior with invalid input
      const sdefType: SDEFType = { kind: 'record', properties: undefined };
      const result = mapper.mapType(sdefType);

      expect(result.type).toBe('object');
      expect(result.properties).toBeDefined();
    });

    it('should handle class reference with undefined className', () => {
      // @ts-expect-error Testing runtime behavior with invalid input
      const sdefType: SDEFType = { kind: 'class', className: undefined };
      const result = mapper.mapType(sdefType);

      expect(result.type).toBe('object');
      expect(result.description).toBeDefined();
    });

    it('should handle enumeration with undefined enumerationName', () => {
      // @ts-expect-error Testing runtime behavior with invalid input
      const sdefType: SDEFType = { kind: 'enumeration', enumerationName: undefined };
      const result = mapper.mapType(sdefType);

      expect(result.type).toBe('string');
      expect(result.description).toBeDefined();
    });
  });

  describe('complex real-world scenarios', () => {
    it('should map Finder open command target parameter type', () => {
      // Finder's open command takes a file reference
      const sdefType: SDEFType = { kind: 'file' };
      const result = mapper.mapType(sdefType);

      expect(result).toEqual({
        type: 'string',
        description: 'File path',
      });
    });

    it('should map Finder duplicate command parameters', () => {
      // duplicate(file, to: file) → list of file
      const targetType: SDEFType = { kind: 'file' };
      const toType: SDEFType = { kind: 'file' };
      const resultType: SDEFType = {
        kind: 'list',
        itemType: { kind: 'file' },
      };

      expect(mapper.mapType(targetType)).toEqual({
        type: 'string',
        description: 'File path',
      });
      expect(mapper.mapType(toType)).toEqual({
        type: 'string',
        description: 'File path',
      });
      expect(mapper.mapType(resultType)).toEqual({
        type: 'array',
        items: { type: 'string', description: 'File path' },
      });
    });

    it('should map Mail compose command with record parameter', () => {
      // Mail's compose command might take a record with multiple properties
      const sdefType: SDEFType = {
        kind: 'record',
        properties: {
          to: {
            kind: 'list',
            itemType: { kind: 'primitive', type: 'text' },
          },
          subject: { kind: 'primitive', type: 'text' },
          body: { kind: 'primitive', type: 'text' },
          visible: { kind: 'primitive', type: 'boolean' },
        },
      };

      const result = mapper.mapType(sdefType);

      expect(result.type).toBe('object');
      expect(result.properties?.to).toEqual({
        type: 'array',
        items: { type: 'string' },
      });
      expect(result.properties?.subject).toEqual({ type: 'string' });
      expect(result.properties?.body).toEqual({ type: 'string' });
      expect(result.properties?.visible).toEqual({ type: 'boolean' });
    });
  });
});
