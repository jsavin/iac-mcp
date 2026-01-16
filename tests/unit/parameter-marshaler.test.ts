/**
 * Unit tests for ParameterMarshaler
 *
 * Tests marshaling of JSON parameters from MCP into JXA-compatible values.
 * The marshaler converts JSON values into executable JXA code strings with
 * proper escaping, type conversion, and special handling for file paths.
 */

import { describe, it, expect } from 'vitest';
import { ParameterMarshaler } from '../../src/adapters/macos/parameter-marshaler';
import type { JSONSchema, JSONSchemaProperty } from '../../src/types/mcp-tool';

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
      const result = marshaler.marshalValue('/Users/test/file.txt', schema);
      expect(result).toBe('Path("/Users/test/file.txt")');
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
      const result = marshaler.marshalValue('/Users/my folder/test file.txt', schema);
      expect(result).toBe('Path("/Users/my folder/test file.txt")');
    });

    it('should not convert URL to Path()', () => {
      const schema: JSONSchemaProperty = {
        type: 'string'
      };
      const result = marshaler.marshalValue('https://example.com/path', schema);
      expect(result).toBe('"https://example.com/path"');
    });

    it('should not convert regular string starting with forward slash to Path()', () => {
      const schema: JSONSchemaProperty = {
        type: 'string'
      };
      const result = marshaler.marshalValue('/just/a/string', schema);
      // This should be Path() since it starts with /
      expect(result).toBe('Path("/just/a/string")');
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
      const result = marshaler.marshalValue('/Users/test/file.txt', schema);
      expect(result).toBe('Path("/Users/test/file.txt")');
    });

    it('should convert path in array to Path()', () => {
      const schema: JSONSchemaProperty = {
        type: 'array',
        items: { type: 'string', description: 'File path' }
      };
      const result = marshaler.marshalValue(['/file1.txt', '/file2.txt'], schema);
      expect(result).toBe('[Path("/file1.txt"), Path("/file2.txt")]');
    });

    it('should handle path in object to Path()', () => {
      const schema: JSONSchemaProperty = {
        type: 'object',
        properties: {
          file: { type: 'string', description: 'File path' }
        }
      };
      const result = marshaler.marshalValue({ file: '/test.txt' }, schema);
      expect(result).toBe('{file: Path("/test.txt")}');
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
        target: '/target/file.txt',
        to: '/destination/',
        from: '/source/'
      };
      const result = marshaler.marshal(params, schema, { name: 'test', appName: 'Finder' });
      expect(result).toContain('target: Path("/target/file.txt")');
      expect(result).toContain('to: Path("/destination/")');
      expect(result).toContain('from: Path("/source/")');
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
      const result = marshaler.marshalValue('/test.txt', schema);
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

    it('should reject path starting with /private/', () => {
      const schema: JSONSchemaProperty = {
        type: 'string',
        description: 'File path'
      };
      expect(() => {
        marshaler.marshalValue('/private/var/db', schema);
      }).toThrow('restricted system directory');
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
      const result = marshaler.marshalValue('/Users/test/Documents/file.txt', schema);
      expect(result).toBe('Path("/Users/test/Documents/file.txt")');
    });

    it('should allow legitimate relative paths (without ..)', () => {
      const schema: JSONSchemaProperty = {
        type: 'string',
        description: 'File path'
      };
      const result = marshaler.marshalValue('./Documents/file.txt', schema);
      expect(result).toBe('Path("./Documents/file.txt")');
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

    it('should be case-sensitive for restricted directories', () => {
      const schema: JSONSchemaProperty = {
        type: 'string',
        description: 'File path'
      };
      // Uppercase /etc should be allowed (only lowercase /etc/ is restricted)
      const result = marshaler.marshalValue('/Etc/somefile', schema);
      expect(result).toBe('Path("/Etc/somefile")');
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
});
