/**
 * Type definitions for JXA (JavaScript for Automation) execution
 */

/**
 * Result of JXA execution
 */
export type JXAExecutionResult<T = unknown> =
  | { success: true; data: T }
  | {
      success: false;
      error: {
        type:
          | 'APP_NOT_FOUND'
          | 'APP_NOT_RUNNING'
          | 'PERMISSION_DENIED'
          | 'INVALID_PARAM'
          | 'EXECUTION_ERROR'
          | 'TIMEOUT';
        message: string;
        appName?: string;
      };
    };

/**
 * Configuration for JXA execution
 */
export interface JXAExecutionConfig {
  timeoutMs?: number;
  requiresApp?: boolean;
  appName?: string;
}

/**
 * JXA script template
 */
export interface JXAScript {
  script: string;
  appName?: string;
  timeout?: number;
}
