/**
 * ErrorHandler - Convert JXAError objects into user-friendly messages with suggestions
 *
 * Classifies execution errors and generates context-specific messages and
 * actionable suggestions for users. Also determines error retryability.
 */

/**
 * Error types from JXA execution
 */
export type JXAErrorType =
  | 'APP_NOT_FOUND'
  | 'APP_NOT_RUNNING'
  | 'PERMISSION_DENIED'
  | 'INVALID_PARAM'
  | 'EXECUTION_ERROR'
  | 'TIMEOUT';

/**
 * JXA error object
 */
export interface JXAError {
  type: JXAErrorType;
  message: string;
  originalError?: string;
}

/**
 * Execution context for error handling
 */
export interface ExecutionContext {
  appName: string;
  commandName: string;
  parameters: Record<string, any>;
}

/**
 * User-friendly error result
 */
export interface HandledError {
  type: string;
  message: string;
  suggestion?: string;
  retryable: boolean;
  originalError: string;
}

/**
 * Error handler for execution errors
 */
export class ErrorHandler {
  /**
   * App-specific messaging preferences
   */
  private appSpecificMessages: Record<string, Record<JXAErrorType, string>> = {
    Finder: {
      APP_NOT_FOUND: "Finder is not installed on this system.",
      APP_NOT_RUNNING: "Finder needs to be running to perform this action.",
      PERMISSION_DENIED: "Permission denied to control Finder.",
      INVALID_PARAM: "Invalid file operation parameters.",
      EXECUTION_ERROR: "Finder encountered an error during file operations.",
      TIMEOUT: "File operation timed out.",
    },
    Safari: {
      APP_NOT_FOUND: "Safari is not installed on this system.",
      APP_NOT_RUNNING: "Safari needs to be running to perform this action.",
      PERMISSION_DENIED: "Permission denied to control Safari.",
      INVALID_PARAM: "Invalid web browsing operation parameters.",
      EXECUTION_ERROR: "Safari encountered an error during the operation.",
      TIMEOUT: "Web operation timed out.",
    },
    Mail: {
      APP_NOT_FOUND: "Mail is not installed on this system.",
      APP_NOT_RUNNING: "Mail needs to be running to perform this action.",
      PERMISSION_DENIED: "Permission denied to control Mail.",
      INVALID_PARAM: "Invalid email operation parameters.",
      EXECUTION_ERROR: "Mail encountered an error during the operation.",
      TIMEOUT: "Email operation timed out.",
    },
    Chrome: {
      APP_NOT_FOUND: "Chrome is not installed on this system.",
      APP_NOT_RUNNING: "Chrome needs to be running to perform this action.",
      PERMISSION_DENIED: "Permission denied to control Chrome.",
      INVALID_PARAM: "Invalid Chrome operation parameters.",
      EXECUTION_ERROR: "Chrome encountered an error during the operation.",
      TIMEOUT: "Chrome operation timed out.",
    },
  };

  /**
   * Generic error message templates
   */
  private genericMessages: Record<JXAErrorType, string> = {
    APP_NOT_FOUND: "{appName} is not installed on this system.",
    APP_NOT_RUNNING: "{appName} needs to be running to perform this action.",
    PERMISSION_DENIED: "Permission denied to control {appName}.",
    INVALID_PARAM: "Invalid parameter for {commandName} command.",
    EXECUTION_ERROR: "{appName} encountered an error while executing {commandName}.",
    TIMEOUT: "Command execution on {appName} timed out.",
  };

  /**
   * Handle execution error and generate user-friendly message
   *
   * @param error - JXA error object
   * @param context - Execution context
   * @returns User-friendly handled error
   */
  handle(error: JXAError, context: ExecutionContext): HandledError {
    // Handle null/undefined gracefully
    if (!error || !context) {
      return {
        type: 'UNKNOWN',
        message: 'An unknown error occurred.',
        retryable: false,
        originalError: error?.originalError || 'Unknown error',
      };
    }

    // Ensure originalError is set
    const originalError = error.originalError || error.message || 'Unknown error';

    // Generate user-friendly message
    const message = this.generateMessage(error.type, context);

    // Generate suggestion
    const suggestion = this.generateSuggestion(error.type, context);

    // Determine if error is retryable
    const retryable = this.isRetryable({
      type: error.type,
      message,
      suggestion,
      retryable: false, // Will be overwritten
      originalError,
    });

    // Log the error
    this.logError(error, context, message);

    return {
      type: error.type,
      message,
      suggestion,
      retryable,
      originalError,
    };
  }

  /**
   * Check if error is retryable
   *
   * @param error - Handled error object
   * @returns True if error is retryable
   */
  isRetryable(error: HandledError): boolean {
    // Only TIMEOUT and APP_NOT_RUNNING are retryable
    return error.type === 'TIMEOUT' || error.type === 'APP_NOT_RUNNING';
  }

  /**
   * Generate user-friendly error message
   *
   * @param errorType - Type of error
   * @param context - Execution context
   * @returns User-friendly message
   */
  private generateMessage(errorType: JXAErrorType, context: ExecutionContext): string {
    const appName = context.appName || 'Application';
    const commandName = context.commandName || 'command';

    // Check for app-specific message
    if (this.appSpecificMessages[appName]) {
      let message = this.appSpecificMessages[appName][errorType];
      message = message.replace('{appName}', appName).replace('{commandName}', commandName);
      return this.capitalizeFirst(message);
    }

    // Use generic template
    let message = this.genericMessages[errorType];
    message = message.replace('{appName}', appName).replace('{commandName}', commandName);

    return this.capitalizeFirst(message);
  }

  /**
   * Generate actionable suggestion
   *
   * @param errorType - Type of error
   * @param context - Execution context
   * @returns Suggestion text
   */
  private generateSuggestion(errorType: JXAErrorType, context: ExecutionContext): string | undefined {
    const appName = context.appName || 'the application';
    const commandName = context.commandName || 'this command';

    switch (errorType) {
      case 'APP_NOT_FOUND':
        return `Please ensure ${appName} is installed on your system.`;

      case 'APP_NOT_RUNNING':
        return `Please launch ${appName} and try again.`;

      case 'PERMISSION_DENIED':
        return `Grant automation permission in System Settings > Privacy & Security > Automation, then allow ${appName}.`;

      case 'INVALID_PARAM':
        return `Check the parameters for ${commandName} and ensure they are valid.`;

      case 'TIMEOUT':
        return `Try the command again or check if ${appName} is responding.`;

      case 'EXECUTION_ERROR':
        return `Check the ${commandName} parameters and ensure ${appName} is in a valid state.`;

      default:
        return undefined;
    }
  }

  /**
   * Capitalize first letter of string
   *
   * @param str - String to capitalize
   * @returns Capitalized string
   */
  private capitalizeFirst(str: string): string {
    if (!str) return str;
    return str.charAt(0).toUpperCase() + str.slice(1);
  }

  /**
   * Log error with context and timestamp
   *
   * @param error - JXA error
   * @param context - Execution context
   * @param userMessage - User-friendly message
   */
  private logError(error: JXAError, context: ExecutionContext, userMessage: string): void {
    const timestamp = new Date().toISOString();

    const logEntry = {
      timestamp,
      errorType: error.type,
      appName: context.appName,
      commandName: context.commandName,
      userMessage,
      technicalError: error.originalError || error.message,
      parameters: context.parameters,
    };

    // Log to console for now (could be extended to file logging)
    console.log('[ErrorHandler]', JSON.stringify(logEntry));
  }
}
