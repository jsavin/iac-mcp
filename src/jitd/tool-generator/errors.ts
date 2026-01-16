/**
 * Custom Error Classes for Tool Generator
 *
 * Provides typed error classes for better error handling and control flow.
 */

/**
 * Base class for all tool generator errors
 */
export class ToolGeneratorError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ToolGeneratorError';
    // Maintains proper stack trace for where error was thrown
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
  }
}

/**
 * Validation errors during tool generation
 *
 * These represent issues with the tool definition that prevent
 * it from being valid according to MCP protocol requirements.
 */
export class ValidationError extends ToolGeneratorError {
  constructor(
    message: string,
    public readonly field: string,
    public readonly severity: 'critical' | 'warning' = 'critical'
  ) {
    super(message);
    this.name = 'ValidationError';
  }

  /**
   * Check if this is a critical error that should block tool generation
   */
  isCritical(): boolean {
    return this.severity === 'critical';
  }
}

/**
 * Errors related to name collision resolution
 */
export class CollisionResolutionError extends ToolGeneratorError {
  constructor(message: string, public readonly baseName: string) {
    super(message);
    this.name = 'CollisionResolutionError';
  }
}

/**
 * Errors related to invalid input data
 */
export class InvalidInputError extends ToolGeneratorError {
  constructor(message: string, public readonly fieldName: string) {
    super(message);
    this.name = 'InvalidInputError';
  }
}
