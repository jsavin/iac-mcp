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
   * - Other patterns can bypass intended application control flow
   *
   * This validation provides defense-in-depth against:
   * - Malicious scripts from untrusted sources
   * - Script injection via template/parameter manipulation
   * - Unintended privilege escalation
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
