/**
 * MacOS Adapter - Main execution orchestrator
 *
 * High-level facade that orchestrates the execution layer components:
 * - ParameterMarshaler: Converts JSON parameters to JXA code
 * - JXAExecutor: Executes JXA scripts via osascript
 * - ResultParser: Parses execution results and classifies errors
 *
 * The adapter is responsible for:
 * 1. Validating tool metadata
 * 2. Marshaling JSON parameters to JXA code
 * 3. Building complete JXA scripts
 * 4. Executing scripts via JXAExecutor
 * 5. Parsing and returning results
 * 6. Handling errors gracefully
 */

import type { MCPTool } from '../../types/mcp-tool.js';
import type { JXAExecutionResult } from '../../types/jxa.js';
import { JXAExecutor } from './jxa-executor.js';
import { ParameterMarshaler } from './parameter-marshaler.js';
import { ResultParser } from './result-parser.js';

/**
 * Adapter configuration options
 */
export interface MacOSAdapterOptions {
  /**
   * Execution timeout in milliseconds
   * Default: 30000 (30 seconds)
   */
  timeoutMs?: number;

  /**
   * Enable verbose logging
   * Default: false
   */
  enableLogging?: boolean;
}

/**
 * MacOS Adapter
 *
 * Main execution facade that coordinates JXA execution, parameter marshaling,
 * and result parsing.
 */
export class MacOSAdapter {
  private executor: JXAExecutor;
  private marshaler: ParameterMarshaler;
  private parser: ResultParser;
  private timeout: number;
  private enableLogging: boolean;

  /**
   * Create a new MacOS adapter
   * @param options - Configuration options
   */
  constructor(options?: MacOSAdapterOptions) {
    this.executor = new JXAExecutor();
    this.marshaler = new ParameterMarshaler();
    this.parser = new ResultParser();
    this.timeout = options?.timeoutMs ?? 30000;
    this.enableLogging = options?.enableLogging ?? false;
  }

  /**
   * Execute an MCP tool on macOS
   *
   * Main entry point for tool execution. Orchestrates the complete flow:
   * 1. Validate tool has metadata
   * 2. Build JXA script (which marshals parameters internally)
   * 3. Execute script
   * 4. Parse result
   *
   * @param tool - Complete MCP tool definition
   * @param args - Arguments from MCP CallTool request
   * @returns Execution result with success/error info
   * @throws Error if tool metadata is missing
   */
  async execute(tool: MCPTool, args: Record<string, any>): Promise<JXAExecutionResult> {
    // Validate tool has metadata
    if (!tool._metadata) {
      throw new Error('Tool metadata is required for execution');
    }

    if (this.enableLogging) {
      console.debug(`[MacOSAdapter] Executing tool: ${tool.name}`, {
        appName: tool._metadata.appName,
        commandName: tool._metadata.commandName,
        args,
      });
    }

    // Build JXA script (this marshals parameters internally)
    const script = this.buildJXAScript(tool, args);

    if (this.enableLogging) {
      console.debug(`[MacOSAdapter] Generated script:`, script);
    }

    // Execute script using JXAExecutor
    const result = await this.executor.execute(script, {
      timeoutMs: this.timeout,
      captureStderr: true,
    });

    if (this.enableLogging) {
      console.debug(`[MacOSAdapter] Execution result:`, {
        exitCode: result.exitCode,
        stdout: result.stdout.substring(0, 200),
        stderr: result.stderr?.substring(0, 200),
        timedOut: result.timedOut,
      });
    }

    // Parse result using ResultParser
    const parsed = this.parser.parse(result, tool._metadata);

    if (this.enableLogging) {
      console.debug(`[MacOSAdapter] Parsed result:`, parsed);
    }

    // Format and return result
    if (parsed.success) {
      return {
        success: true,
        data: parsed.data,
      };
    } else {
      return {
        success: false,
        error: {
          type: parsed.error!.type,
          message: parsed.error!.message,
          appName: tool._metadata.appName,
        },
      };
    }
  }

  /**
   * Build JXA script from tool and arguments
   *
   * Generates a complete JXA IIFE (Immediately Invoked Function Expression)
   * that will be executed via osascript.
   *
   * Template:
   * ```javascript
   * (() => {
   *   const app = Application("{appName}");
   *   app.includeStandardAdditions = true;
   *   const params = {marshaledParams};
   *   const result = app.{commandName}(params);
   *   return result;
   * })()
   * ```
   *
   * @param tool - MCP tool definition
   * @param args - Arguments (for marshaling)
   * @returns JXA script code
   * @throws Error if tool metadata is missing or contains invalid characters
   */
  buildJXAScript(tool: MCPTool, args: Record<string, any>): string {
    // Validate metadata
    if (!tool._metadata) {
      throw new Error('Tool metadata is missing');
    }

    const { appName, commandName } = tool._metadata;

    // Validate appName and commandName to prevent script injection
    this.validateScriptIdentifier('appName', appName);
    this.validateScriptIdentifier('commandName', commandName);

    // Marshal parameters
    const marshaledParams = this.marshaler.marshal(
      args,
      tool.inputSchema,
      tool._metadata
    );

    // Build script as IIFE
    // Use command name, but check if we have parameters
    // For commands with no required parameters, don't pass params object
    const hasRequiredParams = tool.inputSchema?.required && tool.inputSchema.required.length > 0;
    const methodCall = this.buildMethodCall(commandName);

    // Only pass params if there are required parameters
    const methodCall2 = hasRequiredParams ? `${methodCall}(${marshaledParams})` : `${methodCall}()`;

    const script = `(() => {
  const app = Application("${appName}");
  app.includeStandardAdditions = true;
  const result = app${methodCall2};
  return result;
})()`;

    return script;
  }

  /**
   * Build method call syntax for JXA
   *
   * Converts AppleScript command names to JXA-compatible format:
   * - "end session" → endSession (camelCase)
   * - "start new session" → startNewSession (camelCase)
   * - Already camelCase → use as-is
   *
   * JXA requires command names to be valid JavaScript identifiers,
   * so spaces and special characters must be converted to camelCase.
   *
   * @param commandName - The command name from tool metadata (may have spaces)
   * @returns Method call syntax for JXA (e.g., ".endSession")
   */
  private buildMethodCall(commandName: string): string {
    // Convert spaces and hyphens to camelCase
    // "end session" → "endSession"
    // "start-new-session" → "startNewSession"
    // "getVolume" → "getVolume" (preserve if already valid)

    // If it's already a valid identifier with no spaces/hyphens, preserve it
    const hasDelimiters = /[\s-]/.test(commandName);

    let camelCase: string;
    if (!hasDelimiters) {
      // Single word or already camelCase - preserve as-is
      camelCase = commandName;
    } else {
      // Multiple words - convert to camelCase
      camelCase = commandName
        .split(/[\s-]+/) // Split on whitespace or hyphens
        .map((word, index) => {
          if (index === 0) {
            // First word is lowercase
            return word.toLowerCase();
          }
          // Subsequent words: capitalize first letter
          return word.charAt(0).toUpperCase() + word.slice(1).toLowerCase();
        })
        .join('');
    }

    // Check if the result is a valid JavaScript identifier
    const isValidIdentifier = /^[a-zA-Z_$][a-zA-Z0-9_$]*$/.test(camelCase);

    if (isValidIdentifier) {
      // Use dot notation for valid identifiers
      return `.${camelCase}`;
    }

    // Fallback: use bracket notation if something went wrong
    const escaped = camelCase.replace(/"/g, '\\"');
    return `["${escaped}"]`;
  }

  /**
   * Validate script identifiers to prevent injection attacks
   *
   * Rejects strings containing dangerous characters that could break out of
   * the JXA script context:
   * - Quotes (", '): Could break string literals
   * - Backslashes (\): Could escape delimiters
   * - Semicolons (;): Could terminate statements
   * - Backticks (`): Could start template literals
   * - Dollar signs ($): Could introduce template expressions
   * - Parentheses (): Could introduce unintended function calls
   *
   * @param fieldName - Name of the field being validated (for error messages)
   * @param value - Value to validate
   * @throws Error if value contains invalid characters
   */
  private validateScriptIdentifier(fieldName: string, value: string): void {
    const dangerousChars = /["'\\;$`()]/;
    if (dangerousChars.test(value)) {
      throw new Error(
        `Invalid ${fieldName}: contains characters that could enable script injection. ` +
        `Rejected characters: quotes (", '), backslashes (\\), semicolons (;), ` +
        `dollar signs ($), backticks, and parentheses`
      );
    }
  }

  /**
   * Test if an application is available on the system
   *
   * Attempts to verify that an app with the given bundle ID is installed
   * and scriptable. This is useful for checking app availability before
   * attempting to execute commands.
   *
   * @param bundleId - Bundle identifier (e.g., "com.apple.finder")
   * @returns True if app is available, false otherwise
   */
  async testApp(bundleId: string): Promise<boolean> {
    // Build a simple test script that tries to verify app existence
    const script = `(() => {
  try {
    const app = Application.currentApplication();
    app.includeStandardAdditions = true;
    // Try to get app
    const testApp = Application.stringByEvaluatingJavaScriptFromString(
      \`tell application "System Events" to (bundle identifier of application "${bundleId}")\`
    );
    return testApp ? true : false;
  } catch (e) {
    return false;
  }
})()`;

    try {
      const result = await this.executor.execute(script, {
        timeoutMs: 5000, // Shorter timeout for test
      });
      return result.exitCode === 0;
    } catch (error) {
      return false;
    }
  }
}

/**
 * Create a MacOS adapter with default options
 */
export function createMacOSAdapter(options?: MacOSAdapterOptions): MacOSAdapter {
  return new MacOSAdapter(options);
}

export default MacOSAdapter;
