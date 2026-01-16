/**
 * ResultParser - Parse JXA execution results and classify errors
 *
 * Converts raw JXA execution output (stdout/stderr) into structured
 * ParsedResult objects with proper error classification.
 */

/**
 * Raw execution result from JXA executor
 */
export interface ExecutionResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  timedOut?: boolean;
}

/**
 * Tool metadata for type hints
 */
export interface ToolMetadata {
  name?: string;
  appName: string;
  returnType?: string;
}

/**
 * Parsed result with success/error status
 */
export interface ParsedResult {
  success: boolean;
  data?: any;
  error?: JXAError;
}

/**
 * Classified JXA error
 */
export interface JXAError {
  type:
    | 'APP_NOT_FOUND'
    | 'APP_NOT_RUNNING'
    | 'PERMISSION_DENIED'
    | 'INVALID_PARAM'
    | 'EXECUTION_ERROR'
    | 'TIMEOUT';
  message: string;
  originalError?: string;
}

/**
 * Error patterns for classification
 */
const ERROR_PATTERNS = {
  APP_NOT_FOUND: /Application can't be found/i,
  APP_NOT_RUNNING: /Application isn't running/i,
  PERMISSION_DENIED: /Not authorized to send Apple events|Not allowed to send Apple events/i,
  INVALID_PARAM: /Can't get object|Can't make .* into type/i,
  TIMEOUT: /timeout|killed after \d+ seconds/i,
  SYNTAX_ERROR: /Syntax Error/i,
};

/**
 * ResultParser class
 */
export class ResultParser {
  /**
   * Parse JXA execution result
   * @param result - Raw execution result from JXAExecutor
   * @param metadata - Tool metadata (for type hints)
   * @returns Parsed JSON result
   */
  parse(result: ExecutionResult, metadata: ToolMetadata): ParsedResult {
    // Check for timeout first
    if (result.timedOut || result.exitCode === 124) {
      const toolName = metadata.name ? `${metadata.name} ` : '';
      return {
        success: false,
        error: {
          type: 'TIMEOUT',
          message: `Command timeout while executing ${toolName}on ${metadata.appName}`,
          originalError: result.stderr || 'Command execution timeout',
        },
      };
    }

    // Check for errors (non-zero exit code or stderr with error indicators)
    if (result.exitCode !== 0) {
      // If we have stderr, parse it for specific error types
      if (result.stderr.trim()) {
        const error = this.parseError(result.stderr);
        return {
          success: false,
          error,
        };
      }

      // Exit code non-zero but no stderr - generic execution error
      return {
        success: false,
        error: {
          type: 'EXECUTION_ERROR',
          message: `Command failed with exit code ${result.exitCode}`,
          originalError: result.stdout || 'No error details available',
        },
      };
    }

    // Success case - parse stdout
    try {
      const data = this.parseStdout(result.stdout);
      return {
        success: true,
        data,
      };
    } catch (error) {
      // Failed to parse stdout
      return {
        success: false,
        error: {
          type: 'EXECUTION_ERROR',
          message: `Failed to parse execution result: ${error instanceof Error ? error.message : 'Unknown error'}`,
          originalError: result.stdout,
        },
      };
    }
  }

  /**
   * Parse JXA error from stderr
   * @param stderr - Error output
   * @returns Classified error
   */
  parseError(stderr: string): JXAError {
    const trimmedStderr = stderr.trim();

    // Handle empty stderr
    if (!trimmedStderr) {
      return {
        type: 'EXECUTION_ERROR',
        message: 'Command failed with no error details',
        originalError: stderr,
      };
    }

    // Classify error type based on patterns
    let errorType: JXAError['type'] = 'EXECUTION_ERROR';

    if (ERROR_PATTERNS.APP_NOT_FOUND.test(trimmedStderr)) {
      errorType = 'APP_NOT_FOUND';
    } else if (ERROR_PATTERNS.APP_NOT_RUNNING.test(trimmedStderr)) {
      errorType = 'APP_NOT_RUNNING';
    } else if (ERROR_PATTERNS.PERMISSION_DENIED.test(trimmedStderr)) {
      errorType = 'PERMISSION_DENIED';
    } else if (ERROR_PATTERNS.INVALID_PARAM.test(trimmedStderr)) {
      errorType = 'INVALID_PARAM';
    } else if (ERROR_PATTERNS.TIMEOUT.test(trimmedStderr)) {
      errorType = 'TIMEOUT';
    }

    // Extract clean error message
    const message = this.extractErrorMessage(trimmedStderr);

    return {
      type: errorType,
      message,
      originalError: stderr,
    };
  }

  /**
   * Parse stdout into data
   * @param stdout - Raw stdout string
   * @returns Parsed data
   */
  private parseStdout(stdout: string): any {
    const trimmed = stdout.trim();

    // Handle empty stdout (void commands)
    if (!trimmed) {
      return null;
    }

    // Handle undefined
    if (trimmed === 'undefined') {
      return null;
    }

    // Handle Path() expressions - convert to path strings
    if (trimmed.startsWith('Path(')) {
      return this.parsePath(trimmed);
    }

    // Handle arrays or objects that might contain Path() expressions
    if ((trimmed.startsWith('[') || trimmed.startsWith('{')) && trimmed.includes('Path(')) {
      return this.parseWithPaths(trimmed);
    }

    // Try to parse as JSON
    try {
      return JSON.parse(trimmed);
    } catch (error) {
      // Not valid JSON - might be a plain value or malformed
      throw new Error(`Invalid JSON in stdout: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Parse Path() expression
   * @param pathExpr - Path() expression like 'Path("/Users/test")'
   * @returns Extracted path string
   */
  private parsePath(pathExpr: string): string {
    // Match Path("...") with support for escaped quotes and escape sequences
    // Handles: Path("/path/with\"quote.txt"), Path("/path/with\\backslash.txt"), etc.
    const match = pathExpr.match(/Path\("((?:[^"\\]|\\.)*)"\)/);
    if (match && match[1] !== undefined) {
      // Unescape common escape sequences
      return match[1]
        .replace(/\\x22/g, '"') // Hex encoded quote
        .replace(/\\x27/g, "'") // Hex encoded single quote
        .replace(/\\"/g, '"') // Escaped quote
        .replace(/\\'/g, "'") // Escaped single quote
        .replace(/\\\\/g, '\\'); // Escaped backslash (must be last)
    }
    // Fallback - try to extract anything between quotes with escape support
    const fallbackMatch = pathExpr.match(/"((?:[^"\\]|\\.)*)"/) || pathExpr.match(/'((?:[^'\\]|\\.)*)'/) ;
    if (fallbackMatch && fallbackMatch[1] !== undefined) {
      return fallbackMatch[1]
        .replace(/\\x22/g, '"')
        .replace(/\\x27/g, "'")
        .replace(/\\"/g, '"')
        .replace(/\\'/g, "'")
        .replace(/\\\\/g, '\\');
    }
    return pathExpr;
  }

  /**
   * Parse JSON that contains Path() expressions
   * @param jsonWithPaths - JSON string with Path() expressions
   * @returns Parsed object with paths converted to strings
   */
  private parseWithPaths(jsonWithPaths: string): any {
    // Convert Path("...") to "..." for JSON parsing
    const converted = jsonWithPaths.replace(/Path\("([^"]+)"\)/g, '"$1"');

    try {
      return JSON.parse(converted);
    } catch (error) {
      throw new Error(`Invalid JSON with paths: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Extract clean error message from stderr
   * @param stderr - Raw stderr
   * @returns Clean error message
   */
  private extractErrorMessage(stderr: string): string {
    // Remove "execution error:" prefix if present
    let message = stderr.replace(/^execution error:\s*/i, '');

    // Remove "Error:" prefix if present
    message = message.replace(/^Error:\s*/i, '');

    // Take only the first line if multiline
    const lines = message.split('\n');
    const firstLine = (lines[0] ?? '').trim();

    // If we got an empty message somehow, return the original
    if (!firstLine) {
      return stderr.trim();
    }

    // Re-add "Error:" prefix for consistency
    return firstLine.startsWith('Error:') ? firstLine : `Error: ${firstLine}`;
  }
}
