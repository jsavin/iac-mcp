/**
 * Unit tests for ResultParser
 *
 * Tests parsing of JXA execution results into structured ParsedResult objects
 * and classification of errors into specific error types.
 */

import { describe, it, expect } from 'vitest';
import { ResultParser } from '../../src/adapters/macos/result-parser';

interface ExecutionResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  timedOut?: boolean;
}

interface ToolMetadata {
  name: string;
  appName: string;
  returnType?: string;
}

describe('ResultParser', () => {
  const parser = new ResultParser();

  describe('parse() - success cases', () => {
    it('should parse string result', () => {
      const result: ExecutionResult = {
        exitCode: 0,
        stdout: '"hello world"',
        stderr: '',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(true);
      expect(parsed.data).toBe('hello world');
      expect(parsed.error).toBeUndefined();
    });

    it('should parse number result', () => {
      const result: ExecutionResult = {
        exitCode: 0,
        stdout: '42',
        stderr: '',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(true);
      expect(parsed.data).toBe(42);
    });

    it('should parse boolean true result', () => {
      const result: ExecutionResult = {
        exitCode: 0,
        stdout: 'true',
        stderr: '',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(true);
      expect(parsed.data).toBe(true);
    });

    it('should parse boolean false result', () => {
      const result: ExecutionResult = {
        exitCode: 0,
        stdout: 'false',
        stderr: '',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(true);
      expect(parsed.data).toBe(false);
    });

    it('should parse null result', () => {
      const result: ExecutionResult = {
        exitCode: 0,
        stdout: 'null',
        stderr: '',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(true);
      expect(parsed.data).toBeNull();
    });

    it('should parse array result', () => {
      const result: ExecutionResult = {
        exitCode: 0,
        stdout: '[1, 2, 3]',
        stderr: '',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(true);
      expect(parsed.data).toEqual([1, 2, 3]);
    });

    it('should parse object result', () => {
      const result: ExecutionResult = {
        exitCode: 0,
        stdout: '{"name": "test", "value": 123}',
        stderr: '',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(true);
      expect(parsed.data).toEqual({ name: 'test', value: 123 });
    });

    it('should parse empty result (void command)', () => {
      const result: ExecutionResult = {
        exitCode: 0,
        stdout: '',
        stderr: '',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(true);
      expect(parsed.data).toBeNull();
    });

    it('should parse file path result', () => {
      const result: ExecutionResult = {
        exitCode: 0,
        stdout: 'Path("/Users/test/file.txt")',
        stderr: '',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(true);
      expect(parsed.data).toBe('/Users/test/file.txt');
    });

    it('should parse large result', () => {
      const largeArray = new Array(1000).fill(0).map((_, i) => i);
      const result: ExecutionResult = {
        exitCode: 0,
        stdout: JSON.stringify(largeArray),
        stderr: '',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(true);
      expect(parsed.data).toEqual(largeArray);
    });

    it('should parse nested object result', () => {
      const result: ExecutionResult = {
        exitCode: 0,
        stdout: '{"user": {"name": "John", "age": 30}, "active": true}',
        stderr: '',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(true);
      expect(parsed.data).toEqual({
        user: { name: 'John', age: 30 },
        active: true,
      });
    });

    it('should parse array of objects result', () => {
      const result: ExecutionResult = {
        exitCode: 0,
        stdout: '[{"id": 1}, {"id": 2}]',
        stderr: '',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(true);
      expect(parsed.data).toEqual([{ id: 1 }, { id: 2 }]);
    });

    it('should handle whitespace in stdout', () => {
      const result: ExecutionResult = {
        exitCode: 0,
        stdout: '  \n  42  \n  ',
        stderr: '',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(true);
      expect(parsed.data).toBe(42);
    });
  });

  describe('parse() - error cases', () => {
    it('should detect APP_NOT_FOUND error', () => {
      const result: ExecutionResult = {
        exitCode: 1,
        stdout: '',
        stderr: 'Error: Application can\'t be found.',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Safari' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(false);
      expect(parsed.error?.type).toBe('APP_NOT_FOUND');
      expect(parsed.error?.message).toContain('Application can\'t be found');
    });

    it('should detect APP_NOT_RUNNING error', () => {
      const result: ExecutionResult = {
        exitCode: 1,
        stdout: '',
        stderr: 'Error: Application isn\'t running.',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Safari' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(false);
      expect(parsed.error?.type).toBe('APP_NOT_RUNNING');
      expect(parsed.error?.message).toContain('isn\'t running');
    });

    it('should detect PERMISSION_DENIED error', () => {
      const result: ExecutionResult = {
        exitCode: 1,
        stdout: '',
        stderr: 'Error: Not authorized to send Apple events to Finder.',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(false);
      expect(parsed.error?.type).toBe('PERMISSION_DENIED');
      expect(parsed.error?.message).toContain('Not authorized');
    });

    it('should detect INVALID_PARAM error', () => {
      const result: ExecutionResult = {
        exitCode: 1,
        stdout: '',
        stderr: 'Error: Can\'t get object.',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(false);
      expect(parsed.error?.type).toBe('INVALID_PARAM');
      expect(parsed.error?.message).toContain('Can\'t get object');
    });

    it('should detect EXECUTION_ERROR', () => {
      const result: ExecutionResult = {
        exitCode: 1,
        stdout: '',
        stderr: 'Error: Something went wrong.',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(false);
      expect(parsed.error?.type).toBe('EXECUTION_ERROR');
      expect(parsed.error?.message).toContain('Something went wrong');
    });

    it('should detect TIMEOUT error', () => {
      const result: ExecutionResult = {
        exitCode: 124,
        stdout: '',
        stderr: '',
        timedOut: true,
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(false);
      expect(parsed.error?.type).toBe('TIMEOUT');
      expect(parsed.error?.message).toContain('timeout');
    });

    it('should handle unknown error format', () => {
      const result: ExecutionResult = {
        exitCode: 1,
        stdout: '',
        stderr: 'Some random error message',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(false);
      expect(parsed.error?.type).toBe('EXECUTION_ERROR');
      expect(parsed.error?.message).toBeTruthy();
    });

    it('should detect syntax error', () => {
      const result: ExecutionResult = {
        exitCode: 1,
        stdout: '',
        stderr: 'Error: Syntax Error: Expected "," but found "}".',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(false);
      expect(parsed.error?.type).toBe('EXECUTION_ERROR');
      expect(parsed.error?.message).toContain('Syntax Error');
    });

    it('should detect permission error variant', () => {
      const result: ExecutionResult = {
        exitCode: 1,
        stdout: '',
        stderr: 'Error: Not allowed to send Apple events',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(false);
      expect(parsed.error?.type).toBe('PERMISSION_DENIED');
    });

    it('should detect invalid parameter variant', () => {
      const result: ExecutionResult = {
        exitCode: 1,
        stdout: '',
        stderr: 'Error: Can\'t make "invalid" into type reference.',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(false);
      expect(parsed.error?.type).toBe('INVALID_PARAM');
    });
  });

  describe('parseError()', () => {
    it('should classify app not found error', () => {
      const stderr = 'Error: Application can\'t be found.';

      const error = parser.parseError(stderr);

      expect(error.type).toBe('APP_NOT_FOUND');
      expect(error.message).toContain('Application can\'t be found');
      expect(error.originalError).toBe(stderr);
    });

    it('should classify app not running error', () => {
      const stderr = 'Error: Application isn\'t running.';

      const error = parser.parseError(stderr);

      expect(error.type).toBe('APP_NOT_RUNNING');
      expect(error.message).toContain('isn\'t running');
    });

    it('should classify permission denied error', () => {
      const stderr = 'Error: Not authorized to send Apple events to Safari.';

      const error = parser.parseError(stderr);

      expect(error.type).toBe('PERMISSION_DENIED');
      expect(error.message).toContain('Not authorized');
      expect(error.originalError).toBe(stderr);
    });

    it('should classify invalid parameter error', () => {
      const stderr = 'Error: Can\'t get object.';

      const error = parser.parseError(stderr);

      expect(error.type).toBe('INVALID_PARAM');
      expect(error.message).toContain('Can\'t get object');
      expect(error.originalError).toBe(stderr);
    });

    it('should classify timeout error', () => {
      const stderr = 'timeout: the monitored command was killed after 5 seconds';

      const error = parser.parseError(stderr);

      expect(error.type).toBe('TIMEOUT');
      expect(error.message).toContain('timeout');
    });

    it('should extract error message from stderr', () => {
      const stderr = 'execution error: Error: Something bad happened\n    at line 1\n    at line 2';

      const error = parser.parseError(stderr);

      expect(error.message).toBeTruthy();
      expect(error.message.length).toBeGreaterThan(0);
    });

    it('should preserve original error', () => {
      const stderr = 'Error: Test error message';

      const error = parser.parseError(stderr);

      expect(error.originalError).toBe(stderr);
    });

    it('should handle empty stderr', () => {
      const stderr = '';

      const error = parser.parseError(stderr);

      expect(error.type).toBe('EXECUTION_ERROR');
      expect(error.message).toBeTruthy();
    });

    it('should handle multiline error messages', () => {
      const stderr = `Error: Something went wrong
      at line 1
      at line 2`;

      const error = parser.parseError(stderr);

      expect(error.type).toBe('EXECUTION_ERROR');
      expect(error.message).toBeTruthy();
      expect(error.originalError).toBe(stderr);
    });

    it('should extract clean error message', () => {
      const stderr = 'execution error: Error: File not found';

      const error = parser.parseError(stderr);

      expect(error.message).not.toContain('execution error:');
      expect(error.message).toContain('File not found');
    });
  });

  describe('parse() - edge cases', () => {
    it('should handle malformed JSON', () => {
      const result: ExecutionResult = {
        exitCode: 0,
        stdout: '{invalid json}',
        stderr: '',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(false);
      expect(parsed.error?.type).toBe('EXECUTION_ERROR');
    });

    it('should handle very long output', () => {
      const longString = 'x'.repeat(100000);
      const result: ExecutionResult = {
        exitCode: 0,
        stdout: JSON.stringify(longString),
        stderr: '',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(true);
      expect(parsed.data).toBe(longString);
    });

    it('should handle special characters in strings', () => {
      const result: ExecutionResult = {
        exitCode: 0,
        stdout: '"hello\\nworld\\t\\u0041"',
        stderr: '',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(true);
      expect(parsed.data).toBe('hello\nworld\tA');
    });

    it('should handle unicode characters', () => {
      const result: ExecutionResult = {
        exitCode: 0,
        stdout: '"Hello 世界 🌍"',
        stderr: '',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(true);
      expect(parsed.data).toBe('Hello 世界 🌍');
    });

    it('should handle escaped quotes in strings', () => {
      const result: ExecutionResult = {
        exitCode: 0,
        stdout: '"He said \\"hello\\""',
        stderr: '',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(true);
      expect(parsed.data).toBe('He said "hello"');
    });

    it('should handle backslashes in strings', () => {
      const result: ExecutionResult = {
        exitCode: 0,
        stdout: '"C:\\\\Users\\\\test"',
        stderr: '',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(true);
      expect(parsed.data).toBe('C:\\Users\\test');
    });

    it('should handle stdout with trailing newline', () => {
      const result: ExecutionResult = {
        exitCode: 0,
        stdout: '42\n',
        stderr: '',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(true);
      expect(parsed.data).toBe(42);
    });

    it('should handle undefined stdout', () => {
      const result: ExecutionResult = {
        exitCode: 0,
        stdout: 'undefined',
        stderr: '',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(true);
      expect(parsed.data).toBeNull();
    });

    it('should handle mixed stdout and stderr', () => {
      const result: ExecutionResult = {
        exitCode: 0,
        stdout: '42',
        stderr: 'warning: something',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(true);
      expect(parsed.data).toBe(42);
    });

    it('should handle multiple Path() results', () => {
      const result: ExecutionResult = {
        exitCode: 0,
        stdout: '[Path("/file1.txt"), Path("/file2.txt")]',
        stderr: '',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(true);
      expect(Array.isArray(parsed.data)).toBe(true);
    });

    it('should handle Path() in object', () => {
      const result: ExecutionResult = {
        exitCode: 0,
        stdout: '{"file": Path("/test.txt"), "name": "test"}',
        stderr: '',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(true);
      expect(typeof parsed.data).toBe('object');
    });

    it('should handle exit code 0 with error in stderr', () => {
      const result: ExecutionResult = {
        exitCode: 0,
        stdout: '42',
        stderr: 'warning: deprecated method',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(true);
      expect(parsed.data).toBe(42);
    });

    it('should handle exit code non-zero with empty stderr', () => {
      const result: ExecutionResult = {
        exitCode: 1,
        stdout: '',
        stderr: '',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(false);
      expect(parsed.error?.type).toBe('EXECUTION_ERROR');
    });

    it('should handle very large numbers', () => {
      const result: ExecutionResult = {
        exitCode: 0,
        stdout: '9007199254740991',
        stderr: '',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(true);
      expect(parsed.data).toBe(9007199254740991);
    });

    it('should handle decimal numbers', () => {
      const result: ExecutionResult = {
        exitCode: 0,
        stdout: '3.14159',
        stderr: '',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(true);
      expect(parsed.data).toBe(3.14159);
    });

    it('should handle negative numbers', () => {
      const result: ExecutionResult = {
        exitCode: 0,
        stdout: '-42',
        stderr: '',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(true);
      expect(parsed.data).toBe(-42);
    });

    it('should handle scientific notation', () => {
      const result: ExecutionResult = {
        exitCode: 0,
        stdout: '1.23e10',
        stderr: '',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(true);
      expect(parsed.data).toBe(1.23e10);
    });

    it('should handle empty array', () => {
      const result: ExecutionResult = {
        exitCode: 0,
        stdout: '[]',
        stderr: '',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(true);
      expect(parsed.data).toEqual([]);
    });

    it('should handle empty object', () => {
      const result: ExecutionResult = {
        exitCode: 0,
        stdout: '{}',
        stderr: '',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(true);
      expect(parsed.data).toEqual({});
    });

    it('should handle deeply nested structures', () => {
      const result: ExecutionResult = {
        exitCode: 0,
        stdout: '{"a": {"b": {"c": {"d": "deep"}}}}',
        stderr: '',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(true);
      expect(parsed.data).toEqual({ a: { b: { c: { d: 'deep' } } } });
    });

    it('should handle zero', () => {
      const result: ExecutionResult = {
        exitCode: 0,
        stdout: '0',
        stderr: '',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(true);
      expect(parsed.data).toBe(0);
    });

    it('should handle exponential notation with negative exponent', () => {
      const result: ExecutionResult = {
        exitCode: 0,
        stdout: '1.5e-10',
        stderr: '',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(true);
      expect(parsed.data).toBe(1.5e-10);
    });

    it('should handle array with mixed types', () => {
      const result: ExecutionResult = {
        exitCode: 0,
        stdout: '[1, "two", true, null, {"key": "value"}]',
        stderr: '',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(true);
      expect(parsed.data).toEqual([1, 'two', true, null, { key: 'value' }]);
    });

    it('should handle object with null values', () => {
      const result: ExecutionResult = {
        exitCode: 0,
        stdout: '{"name": "test", "value": null}',
        stderr: '',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(true);
      expect(parsed.data).toEqual({ name: 'test', value: null });
    });

    it('should handle string with only whitespace', () => {
      const result: ExecutionResult = {
        exitCode: 0,
        stdout: '"   "',
        stderr: '',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(true);
      expect(parsed.data).toBe('   ');
    });

    it('should handle Path() with spaces in path', () => {
      const result: ExecutionResult = {
        exitCode: 0,
        stdout: 'Path("/Users/my folder/test file.txt")',
        stderr: '',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(true);
      expect(parsed.data).toBe('/Users/my folder/test file.txt');
    });

    it('should handle numbers as strings in JSON', () => {
      const result: ExecutionResult = {
        exitCode: 0,
        stdout: '{"count": 42, "name": "test"}',
        stderr: '',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(true);
      expect(parsed.data).toEqual({ count: 42, name: 'test' });
    });

    it('should handle JSON with escaped forward slashes', () => {
      const result: ExecutionResult = {
        exitCode: 0,
        stdout: '"https:\\/\\/example.com"',
        stderr: '',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(true);
      expect(parsed.data).toBe('https://example.com');
    });

    it('should handle stderr with just whitespace on error', () => {
      const result: ExecutionResult = {
        exitCode: 1,
        stdout: '',
        stderr: '   \n  ',
      };
      const metadata: ToolMetadata = { name: 'test', appName: 'Finder' };

      const parsed = parser.parse(result, metadata);

      expect(parsed.success).toBe(false);
      expect(parsed.error?.type).toBe('EXECUTION_ERROR');
    });
  });
});
