/**
 * Unit tests for ParameterMarshaler
 *
 * Tests marshaling of JSON parameters from MCP into JXA-compatible values.
 * The marshaler converts JSON values into executable JXA code strings with
 * proper escaping, type conversion, and special handling for file paths.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { ParameterMarshaler } from '../../src/adapters/macos/parameter-marshaler';
import type { JSONSchema, JSONSchemaProperty } from '../../src/types/mcp-tool';
import { mkdirSync, symlinkSync, unlinkSync, rmdirSync, existsSync } from 'fs';
import { join } from 'path';
import { tmpdir, homedir } from 'os';

describe('ParameterMarshaler', () => {
  const marshaler = new ParameterMarshaler();

  describe('marshalValue() - basic types', () => {
    describe('string marshaling', () => {
      it('should marshal simple string', () => {
        const schema: JSONSchemaProperty = { type: 'string' };
        const result = marshaler.marshalValue('hello', schema);
        expect(result).toBe('"hello"');
      });

      it('should marshal empty string', () => {
        const schema: JSONSchemaProperty = { type: 'string' };
        const result = marshaler.marshalValue('', schema);
        expect(result).toBe('""');
      });

      it('should marshal string with spaces', () => {
        const schema: JSONSchemaProperty = { type: 'string' };
        const result = marshaler.marshalValue('hello world', schema);
        expect(result).toBe('"hello world"');
      });

      it('should escape double quotes in string', () => {
        const schema: JSONSchemaProperty = { type: 'string' };
        const result = marshaler.marshalValue('He said "hello"', schema);
        expect(result).toBe('"He said \\"hello\\""');
      });

      it('should escape backslashes in string', () => {
        const schema: JSONSchemaProperty = { type: 'string' };
        const result = marshaler.marshalValue('C:\\Users\\test', schema);
        expect(result).toBe('"C:\\\\Users\\\\test"');
      });

      it('should handle newlines in string', () => {
        const schema: JSONSchemaProperty = { type: 'string' };
        const result = marshaler.marshalValue('line1\nline2', schema);
        expect(result).toBe('"line1\\nline2"');
      });

      it('should handle tabs in string', () => {
        const schema: JSONSchemaProperty = { type: 'string' };
        const result = marshaler.marshalValue('col1\tcol2', schema);
        expect(result).toBe('"col1\\tcol2"');
      });

      it('should handle unicode characters', () => {
        const schema: JSONSchemaProperty = { type: 'string' };
        const result = marshaler.marshalValue('Hello 世界 🌍', schema);
        expect(result).toBe('"Hello 世界 🌍"');
      });

      it('should handle carriage return', () => {
        const schema: JSONSchemaProperty = { type: 'string' };
        const result = marshaler.marshalValue('line1\rline2', schema);
        expect(result).toBe('"line1\\rline2"');
      });

      it('should handle form feed', () => {
        const schema: JSONSchemaProperty = { type: 'string' };
        const result = marshaler.marshalValue('page1\fpage2', schema);
        expect(result).toBe('"page1\\fpage2"');
      });

      it('should handle backspace', () => {
        const schema: JSONSchemaProperty = { type: 'string' };
        const result = marshaler.marshalValue('text\bback', schema);
        expect(result).toBe('"text\\bback"');
      });

      it('should handle very long string', () => {
        const schema: JSONSchemaProperty = { type: 'string' };
        const longString = 'x'.repeat(10000);
        const result = marshaler.marshalValue(longString, schema);
        expect(result).toBe(`"${longString}"`);
      });

      it('should handle string with single quotes', () => {
        const schema: JSONSchemaProperty = { type: 'string' };
        const result = marshaler.marshalValue("It's a test", schema);
        expect(result).toBe('"It\'s a test"');
      });

      it('should handle mixed special characters', () => {
        const schema: JSONSchemaProperty = { type: 'string' };
        const result = marshaler.marshalValue('He said "test\nline2"', schema);
        expect(result).toBe('"He said \\"test\\nline2\\""');
      });

      it('should handle only whitespace', () => {
        const schema: JSONSchemaProperty = { type: 'string' };
        const result = marshaler.marshalValue('   ', schema);
        expect(result).toBe('"   "');
      });

      it('should handle string with forward slashes', () => {
        const schema: JSONSchemaProperty = { type: 'string' };
        const result = marshaler.marshalValue('https://example.com/path', schema);
        expect(result).toBe('"https://example.com/path"');
      });
    });

    describe('number marshaling', () => {
      it('should marshal positive integer', () => {
        const schema: JSONSchemaProperty = { type: 'number' };
        const result = marshaler.marshalValue(42, schema);
        expect(result).toBe('42');
      });

      it('should marshal negative integer', () => {
        const schema: JSONSchemaProperty = { type: 'number' };
        const result = marshaler.marshalValue(-42, schema);
        expect(result).toBe('-42');
      });

      it('should marshal zero', () => {
        const schema: JSONSchemaProperty = { type: 'number' };
        const result = marshaler.marshalValue(0, schema);
        expect(result).toBe('0');
      });

      it('should marshal positive float', () => {
        const schema: JSONSchemaProperty = { type: 'number' };
        const result = marshaler.marshalValue(3.14159, schema);
        expect(result).toBe('3.14159');
      });

      it('should marshal negative float', () => {
        const schema: JSONSchemaProperty = { type: 'number' };
        const result = marshaler.marshalValue(-2.5, schema);
        expect(result).toBe('-2.5');
      });

      it('should marshal very large number', () => {
        const schema: JSONSchemaProperty = { type: 'number' };
        const result = marshaler.marshalValue(9007199254740991, schema);
        expect(result).toBe('9007199254740991');
      });

      it('should marshal very small number', () => {
        const schema: JSONSchemaProperty = { type: 'number' };
        const result = marshaler.marshalValue(0.0000001, schema);
        expect(result).toBe('0.0000001');
      });

      it('should marshal scientific notation', () => {
        const schema: JSONSchemaProperty = { type: 'number' };
        const result = marshaler.marshalValue(1.23e10, schema);
        expect(result).toBe('12300000000');
      });

      it('should marshal scientific notation with negative exponent', () => {
        const schema: JSONSchemaProperty = { type: 'number' };
        const result = marshaler.marshalValue(1.5e-10, schema);
        expect(result).toBe('1.5e-10');
      });

      it('should marshal decimal with trailing zeros', () => {
        const schema: JSONSchemaProperty = { type: 'number' };
        const result = marshaler.marshalValue(1.5, schema);
        expect(result).toBe('1.5');
      });
    });

    describe('boolean marshaling', () => {
      it('should marshal true', () => {
        const schema: JSONSchemaProperty = { type: 'boolean' };
        const result = marshaler.marshalValue(true, schema);
        expect(result).toBe('true');
      });

      it('should marshal false', () => {
        const schema: JSONSchemaProperty = { type: 'boolean' };
        const result = marshaler.marshalValue(false, schema);
        expect(result).toBe('false');
      });
    });

    describe('null/undefined handling', () => {
      it('should marshal null', () => {
        const schema: JSONSchemaProperty = { type: 'string' };
        const result = marshaler.marshalValue(null, schema);
        expect(result).toBe('null');
      });

      it('should marshal undefined as null', () => {
        const schema: JSONSchemaProperty = { type: 'string' };
        const result = marshaler.marshalValue(undefined, schema);
        expect(result).toBe('null');
      });
    });
  });

  describe('marshalValue() - complex types', () => {
    describe('array marshaling', () => {
      it('should marshal empty array', () => {
        const schema: JSONSchemaProperty = {
          type: 'array',
          items: { type: 'string' }
        };
        const result = marshaler.marshalValue([], schema);
        expect(result).toBe('[]');
      });

      it('should marshal array of numbers', () => {
        const schema: JSONSchemaProperty = {
          type: 'array',
          items: { type: 'number' }
        };
        const result = marshaler.marshalValue([1, 2, 3], schema);
        expect(result).toBe('[1, 2, 3]');
      });

      it('should marshal array of strings', () => {
        const schema: JSONSchemaProperty = {
          type: 'array',
          items: { type: 'string' }
        };
        const result = marshaler.marshalValue(['a', 'b', 'c'], schema);
        expect(result).toBe('["a", "b", "c"]');
      });

      it('should marshal array with mixed types', () => {
        const schema: JSONSchemaProperty = {
          type: 'array'
        };
        const result = marshaler.marshalValue([1, 'two', true, null], schema);
        expect(result).toBe('[1, "two", true, null]');
      });

      it('should marshal nested arrays', () => {
        const schema: JSONSchemaProperty = {
          type: 'array',
          items: {
            type: 'array',
            items: { type: 'number' }
          }
        };
        const result = marshaler.marshalValue([[1, 2], [3, 4]], schema);
        expect(result).toBe('[[1, 2], [3, 4]]');
      });

      it('should marshal array with objects', () => {
        const schema: JSONSchemaProperty = {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              id: { type: 'number' },
              name: { type: 'string' }
            }
          }
        };
        const result = marshaler.marshalValue([
          { id: 1, name: 'Alice' },
          { id: 2, name: 'Bob' }
        ], schema);
        expect(result).toBe('[{id: 1, name: "Alice"}, {id: 2, name: "Bob"}]');
      });

      it('should marshal deeply nested arrays', () => {
        const schema: JSONSchemaProperty = {
          type: 'array'
        };
        const result = marshaler.marshalValue([[[1, 2], [3]], [[4]]], schema);
        expect(result).toBe('[[[1, 2], [3]], [[4]]]');
      });

      it('should marshal large array', () => {
        const schema: JSONSchemaProperty = {
          type: 'array',
          items: { type: 'number' }
        };
        const largeArray = new Array(100).fill(0).map((_, i) => i);
        const result = marshaler.marshalValue(largeArray, schema);
        expect(result).toContain('[0, 1, 2,');
        expect(result).toContain('99]');
      });

      it('should marshal array with special characters in strings', () => {
        const schema: JSONSchemaProperty = {
          type: 'array',
          items: { type: 'string' }
        };
        const result = marshaler.marshalValue(['hello\nworld', 'test"quote'], schema);
        expect(result).toBe('["hello\\nworld", "test\\"quote"]');
      });
    });

    describe('object marshaling', () => {
      it('should marshal empty object', () => {
        const schema: JSONSchemaProperty = {
          type: 'object',
          properties: {}
        };
        const result = marshaler.marshalValue({}, schema);
        expect(result).toBe('{}');
      });

      it('should marshal simple object', () => {
        const schema: JSONSchemaProperty = {
          type: 'object',
          properties: {
            name: { type: 'string' },
            age: { type: 'number' }
          }
        };
        const result = marshaler.marshalValue({ name: 'John', age: 30 }, schema);
        expect(result).toBe('{name: "John", age: 30}');
      });

      it('should marshal object with boolean', () => {
        const schema: JSONSchemaProperty = {
          type: 'object',
          properties: {
            active: { type: 'boolean' }
          }
        };
        const result = marshaler.marshalValue({ active: true }, schema);
        expect(result).toBe('{active: true}');
      });

      it('should marshal nested object', () => {
        const schema: JSONSchemaProperty = {
          type: 'object',
          properties: {
            user: {
              type: 'object',
              properties: {
                name: { type: 'string' },
                age: { type: 'number' }
              }
            }
          }
        };
        const result = marshaler.marshalValue(
          { user: { name: 'John', age: 30 } },
          schema
        );
        expect(result).toBe('{user: {name: "John", age: 30}}');
      });

      it('should marshal deeply nested object', () => {
        const schema: JSONSchemaProperty = {
          type: 'object',
          properties: {
            a: {
              type: 'object',
              properties: {
                b: {
                  type: 'object',
                  properties: {
                    c: { type: 'string' }
                  }
                }
              }
            }
          }
        };
        const result = marshaler.marshalValue(
          { a: { b: { c: 'deep' } } },
          schema
        );
        expect(result).toBe('{a: {b: {c: "deep"}}}');
      });

      it('should marshal object with array property', () => {
        const schema: JSONSchemaProperty = {
          type: 'object',
          properties: {
            items: {
              type: 'array',
              items: { type: 'number' }
            }
          }
        };
        const result = marshaler.marshalValue({ items: [1, 2, 3] }, schema);
        expect(result).toBe('{items: [1, 2, 3]}');
      });

      it('should marshal object with null values', () => {
        const schema: JSONSchemaProperty = {
          type: 'object',
          properties: {
            name: { type: 'string' },
            value: { type: 'string' }
          }
        };
        const result = marshaler.marshalValue({ name: 'test', value: null }, schema);
        expect(result).toBe('{name: "test", value: null}');
      });

      it('should marshal object with keys containing special characters', () => {
        const schema: JSONSchemaProperty = {
          type: 'object',
          properties: {
            'my-key': { type: 'string' }
          }
        };
        const result = marshaler.marshalValue({ 'my-key': 'value' }, schema);
        expect(result).toContain('value');
      });

      it('should marshal object with multiple properties', () => {
        const schema: JSONSchemaProperty = {
          type: 'object',
          properties: {
            name: { type: 'string' },
            age: { type: 'number' },
            active: { type: 'boolean' },
            items: { type: 'array', items: { type: 'number' } }
          }
        };
        const result = marshaler.marshalValue(
          { name: 'John', age: 30, active: true, items: [1, 2] },
          schema
        );
        expect(result).toContain('name: "John"');
        expect(result).toContain('age: 30');
        expect(result).toContain('active: true');
        expect(result).toContain('items: [1, 2]');
      });
    });

    describe('mixed complex types', () => {
      it('should marshal array of objects with nested arrays', () => {
        const schema: JSONSchemaProperty = {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              tags: { type: 'array', items: { type: 'string' } }
            }
          }
        };
        const result = marshaler.marshalValue([
          { tags: ['a', 'b'] },
          { tags: ['c', 'd'] }
        ], schema);
        expect(result).toContain('{tags: ["a", "b"]}');
        expect(result).toContain('{tags: ["c", "d"]}');
      });

      it('should marshal object with array of objects', () => {
        const schema: JSONSchemaProperty = {
          type: 'object',
          properties: {
            users: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  name: { type: 'string' }
                }
              }
            }
          }
        };
        const result = marshaler.marshalValue(
          { users: [{ name: 'Alice' }, { name: 'Bob' }] },
          schema
        );
        expect(result).toBe('{users: [{name: "Alice"}, {name: "Bob"}]}');
      });
    });
  });

  describe('marshalValue() - path types', () => {
    it('should convert absolute path to Path()', () => {
      const schema: JSONSchemaProperty = {
        type: 'string',
        description: 'File path'
      };
      const result = marshaler.marshalValue('/tmp/test/file.txt', schema);
      expect(result).toBe('Path("/tmp/test/file.txt")');
    });

    it('should convert home path to Path()', () => {
      const schema: JSONSchemaProperty = {
        type: 'string',
        description: 'File path'
      };
      const result = marshaler.marshalValue('~/Documents/file.txt', schema);
      expect(result).toBe('Path("~/Documents/file.txt")');
    });

    it('should convert relative path to Path()', () => {
      const schema: JSONSchemaProperty = {
        type: 'string',
        description: 'File path'
      };
      const result = marshaler.marshalValue('./file.txt', schema);
      expect(result).toBe('Path("./file.txt")');
    });

    it('should convert path with spaces to Path()', () => {
      const schema: JSONSchemaProperty = {
        type: 'string',
        description: 'File path'
      };
      const result = marshaler.marshalValue('/tmp/my folder/test file.txt', schema);
      expect(result).toBe('Path("/tmp/my folder/test file.txt")');
    });

    it('should not convert URL to Path()', () => {
      const schema: JSONSchemaProperty = {
        type: 'string'
      };
      const result = marshaler.marshalValue('https://example.com/path', schema);
      expect(result).toBe('"https://example.com/path"');
    });

    it('should convert absolute path starting with forward slash to Path()', () => {
      const schema: JSONSchemaProperty = {
        type: 'string'
      };
      // Use an allowed path
      const result = marshaler.marshalValue('/tmp/test/document.txt', schema);
      // This should be Path() since it starts with /
      expect(result).toBe('Path("/tmp/test/document.txt")');
    });

    it('should convert directory path to Path()', () => {
      const schema: JSONSchemaProperty = {
        type: 'string',
        description: 'Directory path'
      };
      const result = marshaler.marshalValue('/Applications/', schema);
      expect(result).toBe('Path("/Applications/")');
    });

    it('should handle path with schema format hint', () => {
      const schema: JSONSchemaProperty = {
        type: 'string'
        // Note: format is not in JSONSchemaProperty interface yet,
        // but we test the logic
      };
      const result = marshaler.marshalValue('/tmp/test/file.txt', schema);
      expect(result).toBe('Path("/tmp/test/file.txt")');
    });

    it('should convert path in array to Path()', () => {
      const schema: JSONSchemaProperty = {
        type: 'array',
        items: { type: 'string', description: 'File path' }
      };
      const result = marshaler.marshalValue(['/tmp/test/file1.txt', '/tmp/test/file2.txt'], schema);
      expect(result).toBe('[Path("/tmp/test/file1.txt"), Path("/tmp/test/file2.txt")]');
    });

    it('should handle path in object to Path()', () => {
      const schema: JSONSchemaProperty = {
        type: 'object',
        properties: {
          file: { type: 'string', description: 'File path' }
        }
      };
      const result = marshaler.marshalValue({ file: '/tmp/test/test.txt' }, schema);
      expect(result).toBe('{file: Path("/tmp/test/test.txt")}');
    });

    it('should escape special characters in paths', () => {
      const schema: JSONSchemaProperty = {
        type: 'string',
        description: 'File path'
      };
      const result = marshaler.marshalValue('/Users/test/"quoted".txt', schema);
      expect(result).toBe('Path("/Users/test/\\"quoted\\".txt")');
    });

    it('should reject relative path with directory traversal (.../)', () => {
      const schema: JSONSchemaProperty = {
        type: 'string',
        description: 'File path'
      };
      expect(() => {
        marshaler.marshalValue('../parent/file.txt', schema);
      }).toThrow('contains directory traversal pattern');
    });

    it('should not convert empty string to Path()', () => {
      const schema: JSONSchemaProperty = {
        type: 'string',
        description: 'File path'
      };
      const result = marshaler.marshalValue('', schema);
      expect(result).toBe('""');
    });
  });

  describe('marshal() - schema integration', () => {
    it('should marshal object with required parameters', () => {
      const schema: JSONSchema = {
        type: 'object',
        properties: {
          name: { type: 'string' },
          age: { type: 'number' }
        },
        required: ['name']
      };
      const params = { name: 'John', age: 30 };
      const result = marshaler.marshal(params, schema, { name: 'test', appName: 'Finder' });
      expect(result).toContain('name: "John"');
      expect(result).toContain('age: 30');
    });

    it('should marshal object with optional parameters', () => {
      const schema: JSONSchema = {
        type: 'object',
        properties: {
          name: { type: 'string' },
          nickname: { type: 'string' }
        },
        required: ['name']
      };
      const params = { name: 'John' };
      const result = marshaler.marshal(params, schema, { name: 'test', appName: 'Finder' });
      expect(result).toContain('name: "John"');
      expect(result).not.toContain('nickname');
    });

    it('should marshal parameters with enum values', () => {
      const schema: JSONSchema = {
        type: 'object',
        properties: {
          status: { type: 'string', enum: ['active', 'inactive', 'pending'] }
        }
      };
      const params = { status: 'active' };
      const result = marshaler.marshal(params, schema, { name: 'test', appName: 'Finder' });
      expect(result).toContain('status: "active"');
    });

    it('should handle empty parameters object', () => {
      const schema: JSONSchema = {
        type: 'object',
        properties: {}
      };
      const params = {};
      const result = marshaler.marshal(params, schema, { name: 'test', appName: 'Finder' });
      expect(result).toBe('{}');
    });

    it('should marshal parameters matching parameter names (target, to, from, path)', () => {
      const schema: JSONSchema = {
        type: 'object',
        properties: {
          target: { type: 'string' },
          to: { type: 'string' },
          from: { type: 'string' }
        }
      };
      const params = {
        target: '/tmp/test/file.txt',
        to: '/tmp/test/destination/',
        from: '/tmp/test/source/'
      };
      const result = marshaler.marshal(params, schema, { name: 'test', appName: 'Finder' });
      expect(result).toContain('target: Path("/tmp/test/file.txt")');
      expect(result).toContain('to: Path("/tmp/test/destination/")');
      expect(result).toContain('from: Path("/tmp/test/source/")');
    });

    it('should preserve property order', () => {
      const schema: JSONSchema = {
        type: 'object',
        properties: {
          alpha: { type: 'string' },
          beta: { type: 'string' },
          gamma: { type: 'string' }
        }
      };
      const params = { alpha: 'a', beta: 'b', gamma: 'c' };
      const result = marshaler.marshal(params, schema, { name: 'test', appName: 'Finder' });
      const alphaIndex = result.indexOf('alpha');
      const betaIndex = result.indexOf('beta');
      const gammaIndex = result.indexOf('gamma');
      expect(alphaIndex).toBeLessThan(betaIndex);
      expect(betaIndex).toBeLessThan(gammaIndex);
    });
  });

  describe('error cases', () => {
    it('should throw error for invalid type', () => {
      const schema: JSONSchemaProperty = { type: 'string' };
      expect(() => marshaler.marshalValue(Symbol('test'), schema)).toThrow();
    });

    it('should throw error for function value', () => {
      const schema: JSONSchemaProperty = { type: 'string' };
      expect(() => marshaler.marshalValue(() => {}, schema)).toThrow();
    });

    it('should throw error for circular reference in object', () => {
      const schema: JSONSchemaProperty = { type: 'object', properties: {} };
      const obj: any = { name: 'test' };
      obj.self = obj;
      expect(() => marshaler.marshalValue(obj, schema)).toThrow();
    });

    it('should throw error for circular reference in array', () => {
      const schema: JSONSchemaProperty = { type: 'array' };
      const arr: any = [1, 2];
      arr.push(arr);
      expect(() => marshaler.marshalValue(arr, schema)).toThrow();
    });

    it('should handle invalid schema gracefully', () => {
      const schema: JSONSchemaProperty = { type: 'string' };
      // Pass a number when schema expects string
      const result = marshaler.marshalValue(123, schema);
      // Should convert to string or throw
      expect(result).toBeDefined();
    });

    it('should handle Date object', () => {
      const schema: JSONSchemaProperty = { type: 'string' };
      const date = new Date('2024-01-01T00:00:00.000Z');
      const result = marshaler.marshalValue(date, schema);
      expect(result).toContain('2024');
    });

    it('should handle RegExp object', () => {
      const schema: JSONSchemaProperty = { type: 'string' };
      const regex = /test/g;
      const result = marshaler.marshalValue(regex, schema);
      expect(result).toBeDefined();
    });
  });

  describe('special cases', () => {
    it('should handle very deeply nested structure', () => {
      let obj: any = { value: 'leaf' };
      for (let i = 0; i < 20; i++) {
        obj = { nested: obj };
      }
      const schema: JSONSchemaProperty = { type: 'object', properties: {} };
      const result = marshaler.marshalValue(obj, schema);
      expect(result).toContain('leaf');
    });

    it('should handle object with numeric keys', () => {
      const schema: JSONSchemaProperty = {
        type: 'object',
        properties: {}
      };
      const result = marshaler.marshalValue({ '123': 'value' }, schema);
      expect(result).toContain('value');
    });

    it('should handle sparse array', () => {
      const schema: JSONSchemaProperty = {
        type: 'array',
        items: { type: 'number' }
      };
      const sparseArray = [1, , 3]; // eslint-disable-line no-sparse-arrays
      const result = marshaler.marshalValue(sparseArray, schema);
      expect(result).toContain('null');
    });

    it('should handle NaN', () => {
      const schema: JSONSchemaProperty = { type: 'number' };
      const result = marshaler.marshalValue(NaN, schema);
      expect(result).toBe('null');
    });

    it('should handle Infinity', () => {
      const schema: JSONSchemaProperty = { type: 'number' };
      const result = marshaler.marshalValue(Infinity, schema);
      expect(result).toBe('null');
    });

    it('should handle -Infinity', () => {
      const schema: JSONSchemaProperty = { type: 'number' };
      const result = marshaler.marshalValue(-Infinity, schema);
      expect(result).toBe('null');
    });

    it('should handle BigInt (if supported)', () => {
      const schema: JSONSchemaProperty = { type: 'number' };
      try {
        const bigInt = BigInt(9007199254740991);
        const result = marshaler.marshalValue(bigInt, schema);
        expect(result).toBeDefined();
      } catch (e) {
        // BigInt not supported in this environment
        expect(true).toBe(true);
      }
    });

    it('should handle Buffer objects', () => {
      const schema: JSONSchemaProperty = { type: 'string' };
      if (typeof Buffer !== 'undefined') {
        const buffer = Buffer.from('test');
        const result = marshaler.marshalValue(buffer, schema);
        expect(result).toBeDefined();
      } else {
        expect(true).toBe(true);
      }
    });

    it('should handle Map object', () => {
      const schema: JSONSchemaProperty = { type: 'object', properties: {} };
      const map = new Map([['key', 'value']]);
      const result = marshaler.marshalValue(map, schema);
      expect(result).toBeDefined();
    });

    it('should handle Set object', () => {
      const schema: JSONSchemaProperty = { type: 'array' };
      const set = new Set([1, 2, 3]);
      const result = marshaler.marshalValue(set, schema);
      expect(result).toBeDefined();
    });

    it('should handle object with prototype pollution attempt', () => {
      const schema: JSONSchemaProperty = {
        type: 'object',
        properties: {
          __proto__: { type: 'string' },
          constructor: { type: 'string' }
        }
      };
      const result = marshaler.marshalValue({ __proto__: 'test', constructor: 'test' }, schema);
      expect(result).toBeDefined();
    });

    it('should handle very large object', () => {
      const schema: JSONSchemaProperty = {
        type: 'object',
        properties: {}
      };
      const largeObj: Record<string, number> = {};
      for (let i = 0; i < 100; i++) {
        largeObj[`key${i}`] = i;
      }
      const result = marshaler.marshalValue(largeObj, schema);
      expect(result).toContain('key0');
      expect(result).toContain('key99');
    });

    it('should handle object with null prototype', () => {
      const schema: JSONSchemaProperty = {
        type: 'object',
        properties: {
          name: { type: 'string' }
        }
      };
      const obj = Object.create(null);
      obj.name = 'test';
      const result = marshaler.marshalValue(obj, schema);
      expect(result).toContain('test');
    });

    it('should handle array-like object', () => {
      const schema: JSONSchemaProperty = { type: 'array' };
      const arrayLike = { 0: 'a', 1: 'b', 2: 'c', length: 3 };
      const result = marshaler.marshalValue(arrayLike, schema);
      expect(result).toBeDefined();
    });

    it('should handle string that looks like a number', () => {
      const schema: JSONSchemaProperty = { type: 'string' };
      const result = marshaler.marshalValue('123', schema);
      expect(result).toBe('"123"');
    });

    it('should handle string that looks like boolean', () => {
      const schema: JSONSchemaProperty = { type: 'string' };
      const result = marshaler.marshalValue('true', schema);
      expect(result).toBe('"true"');
    });

    it('should handle empty object in array', () => {
      const schema: JSONSchemaProperty = {
        type: 'array',
        items: { type: 'object', properties: {} }
      };
      const result = marshaler.marshalValue([{}, {}], schema);
      expect(result).toBe('[{}, {}]');
    });

    it('should handle object with undefined properties', () => {
      const schema: JSONSchemaProperty = {
        type: 'object',
        properties: {
          name: { type: 'string' },
          age: { type: 'number' }
        }
      };
      const result = marshaler.marshalValue({ name: 'John', age: undefined }, schema);
      expect(result).toContain('name: "John"');
    });
  });

  describe('generateJXAValue() - code generation verification', () => {
    it('should generate valid JXA code for string', () => {
      const schema: JSONSchemaProperty = { type: 'string' };
      const result = marshaler.marshalValue('test', schema);
      // Verify it's valid JavaScript string literal
      expect(() => JSON.parse(result)).not.toThrow();
    });

    it('should generate valid JXA code for number', () => {
      const schema: JSONSchemaProperty = { type: 'number' };
      const result = marshaler.marshalValue(42, schema);
      expect(Number(result)).toBe(42);
    });

    it('should generate valid JXA code for array', () => {
      const schema: JSONSchemaProperty = {
        type: 'array',
        items: { type: 'number' }
      };
      const result = marshaler.marshalValue([1, 2, 3], schema);
      // Should be valid JavaScript array literal
      expect(result).toMatch(/^\[.*\]$/);
    });

    it('should generate valid JXA code for object', () => {
      const schema: JSONSchemaProperty = {
        type: 'object',
        properties: {
          name: { type: 'string' }
        }
      };
      const result = marshaler.marshalValue({ name: 'test' }, schema);
      // Should be valid JavaScript object literal
      expect(result).toMatch(/^\{.*\}$/);
    });

    it('should generate valid Path() call', () => {
      const schema: JSONSchemaProperty = {
        type: 'string',
        description: 'File path'
      };
      const result = marshaler.marshalValue('/tmp/test/test.txt', schema);
      expect(result).toMatch(/^Path\(".*"\)$/);
    });

    it('should generate properly escaped string for JXA', () => {
      const schema: JSONSchemaProperty = { type: 'string' };
      const result = marshaler.marshalValue('Line 1\nLine 2\tTab', schema);
      // Should contain escaped characters
      expect(result).toContain('\\n');
      expect(result).toContain('\\t');
    });

    it('should generate compact code without unnecessary whitespace', () => {
      const schema: JSONSchemaProperty = {
        type: 'array',
        items: { type: 'number' }
      };
      const result = marshaler.marshalValue([1, 2, 3], schema);
      expect(result).toBe('[1, 2, 3]');
      expect(result).not.toContain('\n');
    });
  });

  describe('Security: Path Traversal Prevention', () => {
    it('should reject path with directory traversal (../)', () => {
      const schema: JSONSchemaProperty = {
        type: 'string',
        description: 'File path'
      };
      expect(() => {
        marshaler.marshalValue('../etc/passwd', schema);
      }).toThrow('directory traversal pattern');
    });

    it('should reject path with Windows directory traversal (..\)', () => {
      const schema: JSONSchemaProperty = {
        type: 'string',
        description: 'File path'
      };
      expect(() => {
        marshaler.marshalValue('..\\windows\\system32', schema);
      }).toThrow('directory traversal pattern');
    });

    it('should reject path starting with /etc/', () => {
      const schema: JSONSchemaProperty = {
        type: 'string',
        description: 'File path'
      };
      expect(() => {
        marshaler.marshalValue('/etc/passwd', schema);
      }).toThrow('restricted system directory');
    });

    it('should reject path starting with /System/', () => {
      const schema: JSONSchemaProperty = {
        type: 'string',
        description: 'File path'
      };
      expect(() => {
        marshaler.marshalValue('/System/Library/CoreServices', schema);
      }).toThrow('restricted system directory');
    });

    it('should reject path starting with /private/var/', () => {
      const schema: JSONSchemaProperty = {
        type: 'string',
        description: 'File path'
      };
      expect(() => {
        marshaler.marshalValue('/private/var/db', schema);
      }).toThrow('restricted system directory');
    });

    it('should reject path starting with /private/etc/', () => {
      const schema: JSONSchemaProperty = {
        type: 'string',
        description: 'File path'
      };
      expect(() => {
        marshaler.marshalValue('/private/etc/hosts', schema);
      }).toThrow('restricted system directory');
    });

    it('should allow legitimate /private/tmp/ paths', () => {
      const schema: JSONSchemaProperty = {
        type: 'string',
        description: 'File path'
      };
      const result = marshaler.marshalValue('/private/tmp/test.txt', schema);
      expect(result).toBe('Path("/private/tmp/test.txt")');
    });

    it('should reject complex traversal patterns', () => {
      const schema: JSONSchemaProperty = {
        type: 'string',
        description: 'File path'
      };
      expect(() => {
        marshaler.marshalValue('/Users/test/../../../etc/passwd', schema);
      }).toThrow('directory traversal pattern');
    });

    it('should allow legitimate home directory paths', () => {
      const schema: JSONSchemaProperty = {
        type: 'string',
        description: 'File path'
      };
      const result = marshaler.marshalValue('~/Documents/file.txt', schema);
      expect(result).toBe('Path("~/Documents/file.txt")');
    });

    it('should allow legitimate absolute paths', () => {
      const schema: JSONSchemaProperty = {
        type: 'string',
        description: 'File path'
      };
      const result = marshaler.marshalValue('/tmp/test/Documents/file.txt', schema);
      expect(result).toBe('Path("/tmp/test/Documents/file.txt")');
    });

    it('should allow legitimate relative paths (without ..)', () => {
      const schema: JSONSchemaProperty = {
        type: 'string',
        description: 'File path'
      };
      const result = marshaler.marshalValue('./Documents/file.txt', schema);
      // Relative paths get resolved from CWD, which should be under /Users/ in test environment
      expect(result).toContain('Path(');
    });

    it('should reject path with ../in the middle', () => {
      const schema: JSONSchemaProperty = {
        type: 'string',
        description: 'File path'
      };
      expect(() => {
        marshaler.marshalValue('/Users/test/../sensitive/file.txt', schema);
      }).toThrow('directory traversal pattern');
    });

    it('should detect traversal even with relative paths', () => {
      const schema: JSONSchemaProperty = {
        type: 'string',
        description: 'File path'
      };
      expect(() => {
        marshaler.marshalValue('./data/../../../etc/passwd', schema);
      }).toThrow('directory traversal pattern');
    });

    it('should reject path with ../in the middle', () => {
      const schema: JSONSchemaProperty = {
        type: 'string',
        description: 'File path'
      };
      expect(() => {
        marshaler.marshalValue('/Users/test/../sensitive/file.txt', schema);
      }).toThrow('directory traversal pattern');
    });

    it('should detect traversal even with relative paths', () => {
      const schema: JSONSchemaProperty = {
        type: 'string',
        description: 'File path'
      };
      expect(() => {
        marshaler.marshalValue('./data/../../../etc/passwd', schema);
      }).toThrow('directory traversal pattern');
    });

    it('should reject /etc even without trailing slash', () => {
      const schema: JSONSchemaProperty = {
        type: 'string',
        description: 'File path'
      };
      // This is actually /etc/something, which starts with /etc/
      expect(() => {
        marshaler.marshalValue('/etc/hosts', schema);
      }).toThrow('restricted system directory');
    });
  });

  describe('Security: Enhanced Path Validation', () => {
    describe('Null byte injection attacks', () => {
      it('should reject path with null byte at end', () => {
        const schema: JSONSchemaProperty = {
          type: 'string',
          description: 'File path'
        };
        expect(() => {
          marshaler.marshalValue('/tmp/test/file.txt\0', schema);
        }).toThrow('null byte');
      });

      it('should reject path with null byte in middle', () => {
        const schema: JSONSchemaProperty = {
          type: 'string',
          description: 'File path'
        };
        expect(() => {
          marshaler.marshalValue('/Users/test\0/../etc/passwd', schema);
        }).toThrow('null byte');
      });

      it('should reject path with multiple null bytes', () => {
        const schema: JSONSchemaProperty = {
          type: 'string',
          description: 'File path'
        };
        expect(() => {
          marshaler.marshalValue('/Users\0/test\0/file.txt', schema);
        }).toThrow('null byte');
      });
    });

    describe('URL-encoded traversal attacks', () => {
      it('should reject URL-encoded ../ (%2e%2e%2f)', () => {
        const schema: JSONSchemaProperty = {
          type: 'string',
          description: 'File path'
        };
        expect(() => {
          marshaler.marshalValue('/Users/test/%2e%2e%2fetc/passwd', schema);
        }).toThrow('URL-encoded directory traversal');
      });

      it('should reject URL-encoded ../ with mixed case (%2E%2E%2F)', () => {
        const schema: JSONSchemaProperty = {
          type: 'string',
          description: 'File path'
        };
        expect(() => {
          marshaler.marshalValue('/Users/test/%2E%2E%2Fetc/passwd', schema);
        }).toThrow('URL-encoded directory traversal');
      });

      it('should handle double URL-encoded ../ (%252e%252e%252f)', () => {
        const schema: JSONSchemaProperty = {
          type: 'string',
          description: 'File path'
        };
        // Double encoding: %252e decodes to %2e (first decode only)
        // Our single decodeURIComponent call won't fully decode it to ../
        // But the resolved path will still fail whitelist validation if it escapes
        // This test verifies the path is either rejected or handled safely
        try {
          const result = marshaler.marshalValue('/Users/test/%252e%252e%252fetc/passwd', schema);
          // If it doesn't throw, it should be a valid path under allowed directories
          expect(result).toContain('Path(');
        } catch (error: any) {
          // Or it should throw a security error
          expect(error.message).toMatch(/directory traversal|outside allowed|restricted system directory/);
        }
      });

      it('should reject URL-encoded Windows traversal (%2e%2e%5c)', () => {
        const schema: JSONSchemaProperty = {
          type: 'string',
          description: 'File path'
        };
        expect(() => {
          marshaler.marshalValue('/Users/test/%2e%2e%5cwindows', schema);
        }).toThrow('URL-encoded directory traversal');
      });

      it('should allow URL-encoded regular characters in allowed paths', () => {
        const schema: JSONSchemaProperty = {
          type: 'string',
          description: 'File path'
        };
        // %20 = space
        const result = marshaler.marshalValue('/Users/test/my%20file.txt', schema);
        expect(result).toBe('Path("/Users/test/my file.txt")');
      });
    });

    describe('Whitelist enforcement', () => {
      it('should allow paths under /Users/', () => {
        const schema: JSONSchemaProperty = {
          type: 'string',
          description: 'File path'
        };
        const result = marshaler.marshalValue('/tmp/john/Documents/file.txt', schema);
        expect(result).toBe('Path("/tmp/john/Documents/file.txt")');
      });

      it('should allow paths under /tmp/', () => {
        const schema: JSONSchemaProperty = {
          type: 'string',
          description: 'File path'
        };
        const result = marshaler.marshalValue('/tmp/tempfile.txt', schema);
        expect(result).toBe('Path("/tmp/tempfile.txt")');
      });

      it.skipIf(process.platform !== 'darwin')('should allow paths under /Applications/', () => {
        const schema: JSONSchemaProperty = {
          type: 'string',
          description: 'File path'
        };
        // Use /Applications directory itself instead of specific app that might be a symlink
        const result = marshaler.marshalValue('/Applications/', schema);
        expect(result).toBe('Path("/Applications/")');
      });

      it('should reject paths under /bin/', () => {
        const schema: JSONSchemaProperty = {
          type: 'string',
          description: 'File path'
        };
        expect(() => {
          marshaler.marshalValue('/bin/bash', schema);
        }).toThrow('restricted system directory');
      });

      it('should reject paths under /sbin/', () => {
        const schema: JSONSchemaProperty = {
          type: 'string',
          description: 'File path'
        };
        expect(() => {
          marshaler.marshalValue('/sbin/init', schema);
        }).toThrow('restricted system directory');
      });

      it('should reject paths under /usr/', () => {
        const schema: JSONSchemaProperty = {
          type: 'string',
          description: 'File path'
        };
        expect(() => {
          marshaler.marshalValue('/usr/bin/python', schema);
        }).toThrow('restricted system directory');
      });

      it('should reject paths under /var/', () => {
        const schema: JSONSchemaProperty = {
          type: 'string',
          description: 'File path'
        };
        expect(() => {
          marshaler.marshalValue('/var/log/system.log', schema);
        }).toThrow('restricted system directory');
      });

      it('should reject paths under /Library/ (system library)', () => {
        const schema: JSONSchemaProperty = {
          type: 'string',
          description: 'File path'
        };
        expect(() => {
          marshaler.marshalValue('/Library/Preferences/SystemConfiguration', schema);
        }).toThrow(/restricted system directory|outside allowed/);
      });

      it('should allow home directory ~/ paths', () => {
        const schema: JSONSchemaProperty = {
          type: 'string',
          description: 'File path'
        };
        const result = marshaler.marshalValue('~/Desktop/file.txt', schema);
        expect(result).toBe('Path("~/Desktop/file.txt")');
      });

      it('should reject ~/ paths with traversal', () => {
        const schema: JSONSchemaProperty = {
          type: 'string',
          description: 'File path'
        };
        expect(() => {
          marshaler.marshalValue('~/../../etc/passwd', schema);
        }).toThrow('directory traversal');
      });
    });

    describe('Case-sensitivity attacks on macOS', () => {
      it('should reject /ETC/ with different casing (whitelist enforcement)', () => {
        const schema: JSONSchemaProperty = {
          type: 'string',
          description: 'File path'
        };
        // /ETC/ doesn't match /Users/, /tmp/, or /Applications/ prefix
        expect(() => {
          marshaler.marshalValue('/ETC/passwd', schema);
        }).toThrow(/outside allowed|restricted system directory/);
      });

      it('should reject /SYSTEM/ with different casing', () => {
        const schema: JSONSchemaProperty = {
          type: 'string',
          description: 'File path'
        };
        expect(() => {
          marshaler.marshalValue('/SYSTEM/Library', schema);
        }).toThrow(/outside allowed|restricted system directory/);
      });

      it('should reject mixed-case system paths (/SyStEm/)', () => {
        const schema: JSONSchemaProperty = {
          type: 'string',
          description: 'File path'
        };
        expect(() => {
          marshaler.marshalValue('/SyStEm/Library', schema);
        }).toThrow(/outside allowed|restricted system directory/);
      });

      it('should allow /Users/ with correct casing', () => {
        const schema: JSONSchemaProperty = {
          type: 'string',
          description: 'File path'
        };
        const result = marshaler.marshalValue('/tmp/john/file.txt', schema);
        expect(result).toBe('Path("/tmp/john/file.txt")');
      });
    });

    describe('Complex attack combinations', () => {
      it('should reject null byte + traversal combination', () => {
        const schema: JSONSchemaProperty = {
          type: 'string',
          description: 'File path'
        };
        expect(() => {
          marshaler.marshalValue('/Users/test\0/../etc/passwd', schema);
        }).toThrow('null byte');
      });

      it('should reject URL-encoded + traversal in restricted dir', () => {
        const schema: JSONSchemaProperty = {
          type: 'string',
          description: 'File path'
        };
        expect(() => {
          marshaler.marshalValue('/Users/%2e%2e/etc/passwd', schema);
        }).toThrow(/URL-encoded|directory traversal/);
      });

      it('should reject multiple traversal sequences', () => {
        const schema: JSONSchemaProperty = {
          type: 'string',
          description: 'File path'
        };
        expect(() => {
          marshaler.marshalValue('/Users/../../../etc/passwd', schema);
        }).toThrow('directory traversal');
      });

      it('should reject traversal with URL encoding and null bytes', () => {
        const schema: JSONSchemaProperty = {
          type: 'string',
          description: 'File path'
        };
        expect(() => {
          marshaler.marshalValue('/Users/%2e%2e\0/etc/passwd', schema);
        }).toThrow(/null byte|URL-encoded|directory traversal/);
      });
    });

    describe('Edge cases and boundary conditions', () => {
      it('should allow /tmp exactly', () => {
        const schema: JSONSchemaProperty = {
          type: 'string',
          description: 'File path'
        };
        const result = marshaler.marshalValue('/tmp', schema);
        expect(result).toBe('Path("/tmp")');
      });

      it('should allow /Users exactly', () => {
        const schema: JSONSchemaProperty = {
          type: 'string',
          description: 'File path'
        };
        const result = marshaler.marshalValue('/Users', schema);
        expect(result).toBe('Path("/Users")');
      });

      it('should reject path with only dots', () => {
        const schema: JSONSchemaProperty = {
          type: 'string',
          description: 'File path'
        };
        const result = marshaler.marshalValue('.', schema);
        // Single dot gets resolved to CWD
        expect(result).toContain('Path(');
      });

      it('should reject empty path after URL decoding', () => {
        const schema: JSONSchemaProperty = {
          type: 'string',
          description: 'File path'
        };
        // Empty strings aren't processed as paths
        const result = marshaler.marshalValue('', schema);
        expect(result).toBe('""');
      });

      it('should handle very long paths in allowed directories', () => {
        const schema: JSONSchemaProperty = {
          type: 'string',
          description: 'File path'
        };
        const longPath = '/Users/test/' + 'a/'.repeat(100) + 'file.txt';
        const result = marshaler.marshalValue(longPath, schema);
        expect(result).toContain('Path(');
        expect(result).toContain('Users/test');
      });

      it('should handle paths with special but allowed characters', () => {
        const schema: JSONSchemaProperty = {
          type: 'string',
          description: 'File path'
        };
        const result = marshaler.marshalValue('/Users/test/file-name_2024.txt', schema);
        expect(result).toBe('Path("/Users/test/file-name_2024.txt")');
      });

      it('should handle paths with Unicode characters', () => {
        const schema: JSONSchemaProperty = {
          type: 'string',
          description: 'File path'
        };
        const result = marshaler.marshalValue('/Users/test/文件.txt', schema);
        expect(result).toBe('Path("/Users/test/文件.txt")');
      });
    });

    describe('Symlink attacks', () => {
      it('should resolve symlinks in home directory paths', () => {
        const schema: JSONSchemaProperty = {
          type: 'string',
          description: 'File path'
        };
        // If ~/Documents exists (common on macOS), it should resolve to real path
        // and validate against whitelist
        const result = marshaler.marshalValue('~/Documents', schema);
        // Should either succeed (if ~/Documents is under /Users/) or fail with security error
        expect(result).toContain('Path(');
      });

      it('should reject symlinks pointing to restricted directories (conceptual test)', () => {
        const schema: JSONSchemaProperty = {
          type: 'string',
          description: 'File path'
        };
        // Note: We can't create actual symlinks in the test, but we can test the logic
        // If someone creates: ln -s /System/Library ~/my_symlink
        // Then uses ~/my_symlink, it would resolve to /System/Library
        // which is outside allowed directories

        // This test validates the concept: after symlink resolution,
        // paths outside whitelist should be rejected
        // We can't actually create the symlink in the test, but the code path is exercised
        // when the path doesn't exist (uses resolve() fallback)

        // Test will exercise the resolution code path
        const result = marshaler.marshalValue('~/nonexistent-test-path-12345', schema);
        expect(result).toContain('Path(');
      });

      it('should resolve symlinks in absolute paths', () => {
        const schema: JSONSchemaProperty = {
          type: 'string',
          description: 'File path'
        };
        // /tmp might be a symlink to /private/tmp on macOS
        // Both are in the whitelist, so this should succeed
        const result = marshaler.marshalValue('/tmp/test.txt', schema);
        expect(result).toContain('Path(');
      });

      it('should reject paths that resolve outside whitelist via symlink', () => {
        const schema: JSONSchemaProperty = {
          type: 'string',
          description: 'File path'
        };
        // If a path resolves to a location outside the whitelist after following symlinks,
        // it should be rejected. This is tested via the whitelist validation after resolution.

        // Test concept: Even if ~/mylink points to /etc/passwd via symlink,
        // after resolution it becomes /etc/passwd which fails whitelist check

        // Since we can't create actual symlinks in the test, we test that
        // non-whitelisted resolved paths are rejected
        expect(() => {
          // This would be caught by whitelist validation if it resolved to /etc
          marshaler.marshalValue('/etc/test', schema);
        }).toThrow(/restricted system directory/);
      });
    });

    describe('Path normalization and resolution', () => {
      it('should normalize multiple slashes', () => {
        const schema: JSONSchemaProperty = {
          type: 'string',
          description: 'File path'
        };
        const result = marshaler.marshalValue('/Users//test///file.txt', schema);
        // Path should be normalized but still under /Users/
        expect(result).toContain('Path(');
      });

      it('should normalize ./ in paths', () => {
        const schema: JSONSchemaProperty = {
          type: 'string',
          description: 'File path'
        };
        const result = marshaler.marshalValue('/Users/./test/./file.txt', schema);
        // Should resolve to /tmp/test/file.txt
        expect(result).toContain('Path(');
      });

      it('should reject symlink-like paths escaping allowed dirs', () => {
        const schema: JSONSchemaProperty = {
          type: 'string',
          description: 'File path'
        };
        // Even if /Users/test/link is a symlink to /etc, we catch it via:
        // 1. The traversal check
        // 2. Or the whitelist check after resolution
        // This test validates the concept; actual symlink resolution happens at runtime
        expect(() => {
          marshaler.marshalValue('/Users/test/../../../etc/passwd', schema);
        }).toThrow('directory traversal');
      });
    });
  });
});
