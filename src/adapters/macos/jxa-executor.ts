/**
 * JXA Executor - Execute JXA scripts via osascript
 *
 * Executes JavaScript for Automation (JXA) scripts in a subprocess using osascript.
 * Handles timeouts, error capture, and output size limiting.
 */

import { execFile } from 'child_process';

/**
 * JXA execution options
 */
export interface JXAExecutionOptions {
  /**
   * Execution timeout in milliseconds
   * Default: 30000 (30 seconds)
   */
  timeoutMs?: number;

  /**
   * Whether to capture stderr
   * Default: true
   */
  captureStderr?: boolean;
}

/**
 * JXA execution result
 */
export interface JXAExecutionResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  timedOut?: boolean;
}

/**
 * Maximum output size (10MB)
 */
const MAX_OUTPUT_SIZE = 10 * 1024 * 1024;

/**
 * Default execution timeout in milliseconds (30 seconds)
 */
const DEFAULT_TIMEOUT_MS = 30000;

/**
 * JXA Executor
 *
 * Executes JavaScript for Automation (JXA) scripts via osascript.
 * Handles resource management, timeouts, and output limiting.
 */
export class JXAExecutor {
  /**
   * Validate JXA script for command injection attempts
   *
   * Security rationale:
   * - JXA scripts run with user privileges and can access AppleEvents
   * - While JXA has a limited sandbox, certain patterns can escape to shell
   * - `do shell script` executes arbitrary shell commands
   * - `system.run()` spawns new processes
   * - eval() and Function() can execute arbitrary code
   * - Template literals can hide dynamic code execution
   * - Encoded strings can bypass pattern matching
   * - Control characters can hide or manipulate script behavior
   * - Other patterns can bypass intended application control flow
   *
   * This validation provides defense-in-depth against:
   * - Malicious scripts from untrusted sources
   * - Script injection via template/parameter manipulation
   * - Unintended privilege escalation
   * - Encoded payload attacks
   * - Control character injection
   *
   * @param script - JXA script to validate
   * @throws Error if dangerous patterns are detected
   */
  private validateScript(script: string): void {
    // Dangerous patterns that can escape JXA sandbox or execute shell commands
    const dangerousPatterns = [
      {
        pattern: /do\s+shell\s+script/i,
        description: 'Shell command execution via AppleScript',
      },
      {
        pattern: /system\.run\s*\(/i,
        description: 'Process spawning via system.run()',
      },
      {
        pattern: /ObjC\.import\s*\(\s*['"]Foundation['"]\s*\)/i,
        description: 'Objective-C bridge to Foundation framework (potential privilege escalation)',
      },
      {
        pattern: /NSTask/i,
        description: 'Process spawning via NSTask',
      },
      {
        pattern: /NSAppleScript/i,
        description: 'Nested AppleScript execution',
      },
      {
        pattern: /@import\s+['"]AppKit['"]/i,
        description: 'AppKit import (potential UI/process manipulation)',
      },
      // NEW: eval() and Function() constructor (arbitrary code execution)
      {
        pattern: /\beval\s*\(/i,
        description: 'Dynamic code execution via eval()',
      },
      {
        pattern: /\bFunction\s*\(/i,
        description: 'Dynamic code execution via Function constructor',
      },
      // NEW: Template literals with expressions (can execute arbitrary code)
      {
        pattern: /`[^`]*\$\{[^}]*\}/,
        description: 'Template literal with expression (potential code execution)',
      },
      // NEW: Base64 encoded strings (can hide malicious payloads)
      {
        pattern: /atob\s*\(/i,
        description: 'Base64 decoding (potential encoded payload)',
      },
      {
        pattern: /btoa\s*\(/i,
        description: 'Base64 encoding (potential obfuscation)',
      },
      // NEW: Hex/octal/unicode escape sequences that could hide code
      {
        pattern: /\\x[0-9a-fA-F]{2}/,
        description: 'Hex escape sequence (potential obfuscation)',
      },
      {
        pattern: /\\u[0-9a-fA-F]{4}/,
        description: 'Unicode escape sequence (potential obfuscation)',
      },
      {
        pattern: /\\[0-7]{1,3}/,
        description: 'Octal escape sequence (potential obfuscation)',
      },
      // NEW: Control characters (null bytes, newlines in strings, etc.)
      {
        pattern: /\x00/,
        description: 'Null byte (control character injection)',
      },
      {
        pattern: /[\x01-\x08\x0B\x0C\x0E-\x1F]/,
        description: 'Control character (potential injection)',
      },
      // NEW: Comment sequences that could hide code execution
      // We intentionally flag suspicious patterns even in comments as a security-first approach
      {
        pattern: /\/\*[^*]*\beval\b[^*]*\*\//i,
        description: 'Suspicious pattern in block comment (eval)',
      },
      {
        pattern: /\/\*[^*]*\bFunction\b[^*]*\*\//i,
        description: 'Suspicious pattern in block comment (Function)',
      },
      {
        pattern: /\/\*[^*]*\bdo\s+shell\b[^*]*\*\//i,
        description: 'Suspicious pattern in block comment (shell)',
      },
      {
        pattern: /\/\/[^\n]*\beval\b/i,
        description: 'Suspicious pattern in line comment (eval)',
      },
      {
        pattern: /\/\/[^\n]*\bFunction\b/i,
        description: 'Suspicious pattern in line comment (Function)',
      },
      {
        pattern: /\/\/[^\n]*\bdo\s+shell\b/i,
        description: 'Suspicious pattern in line comment (shell)',
      },
      // NEW: String concatenation that could build dangerous commands
      // Detect common obfuscation patterns: "do " + "shell", "ev" + "al", etc.
      {
        pattern: /["']do\s*["']\s*\+\s*["']shell/i,
        description: 'String concatenation building "do shell" command',
      },
      {
        pattern: /["']ev["']\s*\+\s*["']al["']/i,
        description: 'String concatenation building "eval" function name',
      },
      {
        pattern: /["']Func["']\s*\+\s*["']tion["']/i,
        description: 'String concatenation building "Function" constructor name',
      },
      // NEW: Dynamic property access that could hide method calls
      {
        pattern: /\[["'](?:eval|Function|exec)["']\]/i,
        description: 'Dynamic property access to dangerous function',
      },
    ];

    for (const { pattern, description } of dangerousPatterns) {
      if (pattern.test(script)) {
        throw new Error(
          `Command injection attempt detected: ${description}. ` +
          `Script validation failed for security reasons.`
        );
      }
    }
  }

  /**
   * Execute a JXA script via osascript
   *
   * Runs a JXA script in a subprocess with:
   * - Script validation (command injection protection)
   * - Timeout protection
   * - stderr capture
   * - Output size limiting (10MB max)
   * - Clean resource cleanup
   *
   * @param script - JXA script to execute
   * @param options - Execution options
   * @returns Execution result with stdout/stderr and exit code
   * @throws Error if script validation fails, execution fails, or timeout occurs
   */
  async execute(script: string, options?: JXAExecutionOptions): Promise<JXAExecutionResult> {
    // Validate script for command injection attempts before execution
    this.validateScript(script);

    const timeoutMs = options?.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const captureStderr = options?.captureStderr !== false;

    return new Promise((resolve) => {
      let resolved = false;
      let stdout = '';
      let stderr = '';

      // Execute osascript with JXA script
      const child = execFile('osascript', ['-l', 'JavaScript', '-'], {
        timeout: timeoutMs,
        maxBuffer: MAX_OUTPUT_SIZE,
        encoding: 'utf-8',
      });

      // Handle stdout data
      if (child.stdout) {
        child.stdout.on('data', (data: string) => {
          stdout += data;

          // Check output size limit
          if (stdout.length > MAX_OUTPUT_SIZE) {
            stdout = stdout.substring(0, MAX_OUTPUT_SIZE);
            child.kill();
          }
        });
      }

      // Handle stderr data
      if (child.stderr && captureStderr) {
        child.stderr.on('data', (data: string) => {
          stderr += data;

          // Check output size limit
          if (stderr.length > MAX_OUTPUT_SIZE) {
            stderr = stderr.substring(0, MAX_OUTPUT_SIZE);
            child.kill();
          }
        });
      }

      // Handle process exit
      child.on('exit', (exitCode: number | null) => {
        // Prevent double-resolution due to race conditions
        if (resolved) {
          return;
        }
        resolved = true;

        resolve({
          exitCode: exitCode ?? 1,
          stdout,
          stderr,
          timedOut: false,
        });
      });

      // Handle process error (e.g., timeout)
      child.on('error', (error: any) => {
        // Prevent double-resolution due to race conditions
        if (resolved) {
          return;
        }
        resolved = true;

        // Check if this is a timeout error
        const isTimeout = error.code === 'ETIMEDOUT' || error.killed === true;

        resolve({
          exitCode: 1,
          stdout,
          stderr: stderr || error.message,
          timedOut: isTimeout,
        });
      });

      // Send script to osascript
      if (child.stdin) {
        child.stdin.write(script);
        child.stdin.end();
      }
    });
  }
}

export default JXAExecutor;
