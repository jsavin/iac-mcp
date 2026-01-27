import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { execFile } from 'child_process';
import { EventEmitter } from 'events';
import { QueryExecutor, QueryParams, CalendarEvent } from '../../src/query-executor/index.js';

// Mock child_process
vi.mock('child_process');

// Mock ChildProcess for JXA execution
class MockChildProcess extends EventEmitter {
  stdout = new EventEmitter();
  stderr = new EventEmitter();
  stdin = {
    write: vi.fn(),
    end: vi.fn(),
    on: vi.fn(),
  };

  constructor(
    private stdoutData: string,
    private stderrData: string,
    private exitCode: number
  ) {
    super();
  }

  kill = vi.fn(() => {
    this.emit('exit', null);
  });

  simulateExecution() {
    if (this.stdoutData) {
      (this.stdout as any).emit('data', this.stdoutData);
    }
    if (this.stderrData) {
      (this.stderr as any).emit('data', this.stderrData);
    }
    this.emit('exit', this.exitCode);
  }
}

// Helper to mock execFile with proper callback behavior
function mockExecFileSuccess(stdout: string, stderr = '') {
  const mockProcess = new MockChildProcess(stdout, stderr, 0);
  vi.mocked(execFile).mockImplementation((cmd, args, options, callback) => {
    setImmediate(() => {
      if (callback) {
        callback(null, stdout, stderr);
      }
    });
    return mockProcess as any;
  });
  return mockProcess;
}

describe('QueryExecutor', () => {
  let executor: QueryExecutor;

  beforeEach(() => {
    executor = new QueryExecutor();
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('generateJXAScript', () => {
    it('should generate script for "today" time range', () => {
      const params: QueryParams = {
        app: 'Calendar',
        timeRange: 'today',
      };

      const script = executor.generateJXAScript(params);

      expect(script).toContain('const app = Application("Calendar")');
      expect(script).toContain('app.calendars'); // All calendars
      expect(script).toContain('startDate >= filterDate');
      expect(script).toContain('JSON.stringify');
    });

    it('should generate script for "this_week" time range', () => {
      const params: QueryParams = {
        app: 'Calendar',
        timeRange: 'this_week',
      };

      const script = executor.generateJXAScript(params);

      expect(script).toContain('const app = Application("Calendar")');
      expect(script).toContain('startDate >= filterDate');
    });

    it('should generate script for "this_month" time range', () => {
      const params: QueryParams = {
        app: 'Calendar',
        timeRange: 'this_month',
      };

      const script = executor.generateJXAScript(params);

      expect(script).toContain('const app = Application("Calendar")');
      expect(script).toContain('startDate >= filterDate');
    });

    it('should generate script for "all" time range', () => {
      const params: QueryParams = {
        app: 'Calendar',
        timeRange: 'all',
      };

      const script = executor.generateJXAScript(params);

      expect(script).toContain('const app = Application("Calendar")');
      expect(script).toContain('startDate >= filterDate');
    });

    it('should include calendar name filter when provided', () => {
      const params: QueryParams = {
        app: 'Calendar',
        timeRange: 'today',
        calendarName: 'Work',
      };

      const script = executor.generateJXAScript(params);

      expect(script).toContain('byName("Work")');
    });

    it('should access all calendars when no calendar name provided', () => {
      const params: QueryParams = {
        app: 'Calendar',
        timeRange: 'today',
      };

      const script = executor.generateJXAScript(params);

      expect(script).toContain('app.calendars');
      expect(script).not.toContain('byName');
    });

    it('should map events to include required fields', () => {
      const params: QueryParams = {
        app: 'Calendar',
        timeRange: 'today',
      };

      const script = executor.generateJXAScript(params);

      expect(script).toContain('summary: e.summary()');
      expect(script).toContain('startDate: e.startDate().toISOString()');
      expect(script).toContain('endDate: e.endDate().toISOString()');
      expect(script).toContain('location');
    });

    it('should include filter logic in generated script', () => {
      const params: QueryParams = {
        app: 'Calendar',
        timeRange: 'today',
      };

      const script = executor.generateJXAScript(params);

      expect(script).toContain('filter');
      expect(script).toContain('startDate >= filterDate');
    });
  });

  describe('getFilterDate', () => {
    it('should return start of today for "today"', () => {
      const now = new Date('2024-01-15T14:30:00Z');
      const result = executor.getFilterDate('today', now);

      expect(result.getHours()).toBe(0);
      expect(result.getMinutes()).toBe(0);
      expect(result.getSeconds()).toBe(0);
      expect(result.getMilliseconds()).toBe(0);
      expect(result.getDate()).toBe(15);
    });

    it('should return start of week for "this_week" (Sunday)', () => {
      // January 15, 2024 is a Monday
      const now = new Date('2024-01-15T14:30:00Z');
      const result = executor.getFilterDate('this_week', now);

      expect(result.getDay()).toBe(0); // Sunday
      expect(result.getHours()).toBe(0);
      expect(result.getMinutes()).toBe(0);
    });

    it('should return start of week when today is Sunday', () => {
      // January 14, 2024 is a Sunday
      const now = new Date('2024-01-14T14:30:00Z');
      const result = executor.getFilterDate('this_week', now);

      expect(result.getDay()).toBe(0); // Sunday
      expect(result.getDate()).toBe(14);
    });

    it('should return start of week when today is Saturday', () => {
      // January 20, 2024 is a Saturday
      const now = new Date('2024-01-20T14:30:00Z');
      const result = executor.getFilterDate('this_week', now);

      expect(result.getDay()).toBe(0); // Sunday
      expect(result.getDate()).toBe(14);
    });

    it('should return start of month for "this_month"', () => {
      const now = new Date('2024-01-15T14:30:00Z');
      const result = executor.getFilterDate('this_month', now);

      expect(result.getDate()).toBe(1);
      expect(result.getHours()).toBe(0);
      expect(result.getMinutes()).toBe(0);
    });

    it('should return far past date for "all"', () => {
      const now = new Date('2024-01-15T14:30:00Z');
      const result = executor.getFilterDate('all', now);

      expect(result.getFullYear()).toBe(1900);
      expect(result.getMonth()).toBe(0); // January
      expect(result.getDate()).toBe(1);
    });

    it('should throw error for invalid time range', () => {
      const now = new Date('2024-01-15T14:30:00Z');

      expect(() => {
        executor.getFilterDate('invalid' as any, now);
      }).toThrow('Invalid time range: invalid');
    });

    it('should normalize time to midnight for "today"', () => {
      const now = new Date('2024-01-15T23:59:59.999Z');
      const result = executor.getFilterDate('today', now);

      expect(result.getHours()).toBe(0);
      expect(result.getMinutes()).toBe(0);
      expect(result.getSeconds()).toBe(0);
      expect(result.getMilliseconds()).toBe(0);
    });
  });

  describe('executeJXA', () => {
    it('should execute JXA script successfully', async () => {
      mockExecFileSuccess('{"result": "success"}\n');

      const script = 'return "test"';
      const result = await executor.executeJXA(script);

      expect(result).toBe('{"result": "success"}');
      expect(execFile).toHaveBeenCalledWith(
        'osascript',
        ['-l', 'JavaScript', '-e', script],
        { timeout: 30000 },
        expect.any(Function)
      );
    });

    it('should trim whitespace from output', async () => {
      mockExecFileSuccess('  result  \n');

      const result = await executor.executeJXA('return "test"');

      expect(result).toBe('result');
    });

    it('should handle execution error', async () => {
      const mockProcess = new MockChildProcess('', 'Error: App not found\n', 1);
      vi.mocked(execFile).mockImplementation((cmd, args, options, callback) => {
        if (callback) {
          callback(new Error('Command failed'), '', 'Error: App not found\n');
        }
        return mockProcess as any;
      });

      const promise = executor.executeJXA('invalid script');

      await expect(promise).rejects.toThrow('JXA execution failed: Error: App not found');
    });

    it('should handle stderr in error message', async () => {
      const mockProcess = new MockChildProcess('', 'Syntax Error\n', 1);
      vi.mocked(execFile).mockImplementation((cmd, args, options, callback) => {
        if (callback) {
          callback(new Error('Command failed'), '', 'Syntax Error\n');
        }
        return mockProcess as any;
      });

      const promise = executor.executeJXA('bad { syntax }');

      await expect(promise).rejects.toThrow('JXA execution failed: Syntax Error');
    });

    it('should use error message when stderr is empty', async () => {
      const mockProcess = new MockChildProcess('', '', 1);
      const error = new Error('Process exited with code 1');
      vi.mocked(execFile).mockImplementation((cmd, args, options, callback) => {
        if (callback) {
          callback(error, '', '');
        }
        return mockProcess as any;
      });

      const promise = executor.executeJXA('script');

      await expect(promise).rejects.toThrow('JXA execution failed: Process exited with code 1');
    });

    it('should set timeout to 30 seconds', async () => {
      mockExecFileSuccess('result\n');

      await executor.executeJXA('return "test"');

      expect(execFile).toHaveBeenCalledWith(
        'osascript',
        expect.any(Array),
        { timeout: 30000 },
        expect.any(Function)
      );
    });
  });

  describe('executeQuery', () => {
    it('should execute query with timeRange="today"', async () => {
      const mockEvents = [
        {
          summary: 'Team Meeting',
          startDate: '2024-01-15T10:00:00Z',
          endDate: '2024-01-15T11:00:00Z',
        },
      ];

      mockExecFileSuccess(JSON.stringify(mockEvents) + '\n', '', 0);

      const params: QueryParams = {
        app: 'Calendar',
        timeRange: 'today',
      };

      const result = await executor.executeQuery(params);

      expect(result).toEqual(mockEvents);
      expect(execFile).toHaveBeenCalled();
    });

    it('should execute query with calendar name filter', async () => {
      const mockEvents = [
        {
          summary: 'Work Task',
          startDate: '2024-01-15T09:00:00Z',
          endDate: '2024-01-15T10:00:00Z',
        },
      ];

      mockExecFileSuccess(JSON.stringify(mockEvents) + '\n', '', 0);

      const params: QueryParams = {
        app: 'Calendar',
        timeRange: 'today',
        calendarName: 'Work',
      };

      const result = await executor.executeQuery(params);

      expect(result).toEqual(mockEvents);

      // Verify script generation included calendar filter
      const callArgs = vi.mocked(execFile).mock.calls[0];
      const script = callArgs[1]![3] as string;
      expect(script).toContain('byName("Work")');
    });

    it('should return array of events', async () => {
      const mockEvents = [
        {
          summary: 'Event 1',
          startDate: '2024-01-15T10:00:00Z',
          endDate: '2024-01-15T11:00:00Z',
        },
        {
          summary: 'Event 2',
          startDate: '2024-01-15T14:00:00Z',
          endDate: '2024-01-15T15:00:00Z',
        },
      ];

      mockExecFileSuccess(JSON.stringify(mockEvents) + '\n', '', 0);

      const params: QueryParams = {
        app: 'Calendar',
        timeRange: 'this_week',
      };

      const result = await executor.executeQuery(params);

      expect(Array.isArray(result)).toBe(true);
      expect(result).toHaveLength(2);
      expect(result[0].summary).toBe('Event 1');
      expect(result[1].summary).toBe('Event 2');
    });

    it('should handle empty result', async () => {
      mockExecFileSuccess('[]\n', '', 0);

      const params: QueryParams = {
        app: 'Calendar',
        timeRange: 'today',
      };

      const result = await executor.executeQuery(params);

      expect(result).toEqual([]);
    });

    it('should handle app not found error', async () => {
      const mockProcess = new MockChildProcess('', 'Error: Application not found\n', 1);
      vi.mocked(execFile).mockImplementation((cmd, args, options, callback) => {
        if (callback) {
          callback(new Error('Command failed'), '', 'Error: Application not found\n');
        }
        return mockProcess as any;
      });

      const params: QueryParams = {
        app: 'NonExistentApp',
        timeRange: 'today',
      };

      await expect(executor.executeQuery(params)).rejects.toThrow(
        'JXA execution failed: Error: Application not found'
      );
    });

    it('should handle permission denied error', async () => {
      const mockProcess = new MockChildProcess(
        '',
        'Error: Not authorized to send Apple events\n',
        1
      );
      vi.mocked(execFile).mockImplementation((cmd, args, options, callback) => {
        if (callback) {
          callback(
            new Error('Command failed'),
            '',
            'Error: Not authorized to send Apple events\n'
          );
        }
        return mockProcess as any;
      });

      const params: QueryParams = {
        app: 'Calendar',
        timeRange: 'today',
      };

      await expect(executor.executeQuery(params)).rejects.toThrow(
        'JXA execution failed: Error: Not authorized to send Apple events'
      );
    });

    it('should handle invalid JSON response', async () => {
      mockExecFileSuccess('invalid json\n', '', 0);

      const params: QueryParams = {
        app: 'Calendar',
        timeRange: 'today',
      };

      const promise = executor.executeQuery(params);

      await expect(promise).rejects.toThrow(/Failed to parse Calendar.app response as JSON/);
    });

    it('should handle malformed JSON response', async () => {
      mockExecFileSuccess('{ "incomplete": \n', '', 0);

      const params: QueryParams = {
        app: 'Calendar',
        timeRange: 'today',
      };

      const promise = executor.executeQuery(params);

      await expect(promise).rejects.toThrow(/Failed to parse Calendar.app response as JSON/);
    });

    it('should parse valid JSON with complex event data', async () => {
      const mockEvents = [
        {
          summary: 'Team Meeting',
          startDate: '2024-01-15T10:00:00Z',
          endDate: '2024-01-15T11:00:00Z',
          location: 'Conference Room A',
        },
      ];

      mockExecFileSuccess(JSON.stringify(mockEvents) + '\n', '', 0);

      const params: QueryParams = {
        app: 'Calendar',
        timeRange: 'today',
      };

      const result = await executor.executeQuery(params);

      expect(result).toEqual(mockEvents);
      expect(result[0].location).toBe('Conference Room A');
    });
  });

  describe('edge cases', () => {
    it('should handle very long event summaries', async () => {
      const longSummary = 'A'.repeat(1000);
      const mockEvents = [
        {
          summary: longSummary,
          startDate: '2024-01-15T10:00:00Z',
          endDate: '2024-01-15T11:00:00Z',
        },
      ];

      mockExecFileSuccess(JSON.stringify(mockEvents) + '\n', '', 0);

      const params: QueryParams = {
        app: 'Calendar',
        timeRange: 'today',
      };

      const result = await executor.executeQuery(params);

      expect(result[0].summary).toBe(longSummary);
    });

    it('should handle special characters in calendar name', async () => {
      const params: QueryParams = {
        app: 'Calendar',
        timeRange: 'today',
        calendarName: "John's Work Calendar",
      };

      const script = executor.generateJXAScript(params);

      expect(script).toContain("John's Work Calendar");
    });

    it('should handle events with missing location', async () => {
      const mockEvents = [
        {
          summary: 'Virtual Meeting',
          startDate: '2024-01-15T10:00:00Z',
          endDate: '2024-01-15T11:00:00Z',
          location: undefined,
        },
      ];

      mockExecFileSuccess(JSON.stringify(mockEvents) + '\n', '', 0);

      const params: QueryParams = {
        app: 'Calendar',
        timeRange: 'today',
      };

      const result = await executor.executeQuery(params);

      expect(result[0].location).toBeUndefined();
    });

    it('should handle dates at year boundaries', () => {
      const newYearsEve = new Date('2024-12-31T23:59:59Z');
      const result = executor.getFilterDate('this_month', newYearsEve);

      expect(result.getFullYear()).toBe(2024);
      expect(result.getMonth()).toBe(11); // December
      expect(result.getDate()).toBe(1);
    });

    it('should handle leap year dates', () => {
      const leapDay = new Date('2024-02-29T12:00:00Z');
      const result = executor.getFilterDate('this_month', leapDay);

      expect(result.getFullYear()).toBe(2024);
      expect(result.getMonth()).toBe(1); // February
      expect(result.getDate()).toBe(1);
    });

    it('should handle timezone-aware dates', () => {
      const now = new Date('2024-01-15T23:30:00-08:00'); // Late evening PST
      const result = executor.getFilterDate('today', now);

      // Should normalize to midnight of the current day
      expect(result.getHours()).toBe(0);
      expect(result.getMinutes()).toBe(0);
    });
  });

  describe('error scenarios', () => {
    it('should propagate network-like errors', async () => {
      const error = new Error('Network timeout');
      vi.mocked(execFile).mockImplementation((cmd, args, options, callback) => {
        if (callback) {
          callback(error, '', '');
        }
        return new MockChildProcess('', '', 1) as any;
      });

      const params: QueryParams = {
        app: 'Calendar',
        timeRange: 'today',
      };

      await expect(executor.executeQuery(params)).rejects.toThrow(
        'JXA execution failed: Network timeout'
      );
    });

    it('should handle script timeout', async () => {
      const error = new Error('Command execution timed out');
      vi.mocked(execFile).mockImplementation((cmd, args, options, callback) => {
        if (callback) {
          callback(error, '', '');
        }
        return new MockChildProcess('', '', 1) as any;
      });

      const params: QueryParams = {
        app: 'Calendar',
        timeRange: 'today',
      };

      await expect(executor.executeQuery(params)).rejects.toThrow('JXA execution failed');
    });

    it('should handle large result sets', async () => {
      // Create 1000 events
      const largeEventSet = Array.from({ length: 1000 }, (_, i) => ({
        summary: `Event ${i}`,
        startDate: '2024-01-15T10:00:00Z',
        endDate: '2024-01-15T11:00:00Z',
      }));

      mockExecFileSuccess(JSON.stringify(largeEventSet) + '\n', '', 0);

      const params: QueryParams = {
        app: 'Calendar',
        timeRange: 'all',
      };

      const result = await executor.executeQuery(params);

      expect(result).toHaveLength(1000);
    });
  });
});
