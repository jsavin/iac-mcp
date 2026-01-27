/**
 * Query executor for Calendar.app
 * Generates and executes JXA scripts to query Calendar events
 */

import { execFile } from 'child_process';
import { QueryParams, CalendarEvent } from './types.js';
import { generateJXAScript, getFilterDate } from './jxa-generator.js';

/**
 * Maximum allowed length for calendar names
 */
const MAX_CALENDAR_NAME_LENGTH = 100;

/**
 * Allowed time range values
 */
const ALLOWED_TIME_RANGES = ['today', 'this_week', 'this_month', 'all'] as const;

/**
 * QueryExecutor class for executing Calendar.app queries
 */
export class QueryExecutor {
  /**
   * Validate query parameters before execution
   * @throws Error if parameters are invalid
   */
  private validateParams(params: QueryParams): void {
    // Validate timeRange against allowed values
    if (!ALLOWED_TIME_RANGES.includes(params.timeRange)) {
      const allowed = ALLOWED_TIME_RANGES.join(', ');
      throw new Error(
        `Invalid timeRange: "${params.timeRange}". Allowed values: ${allowed}`
      );
    }

    // Validate app parameter (must be non-empty)
    if (!params.app || typeof params.app !== 'string' || params.app.trim() === '') {
      throw new Error('App parameter must be a non-empty string');
    }

    // Validate calendarName if provided
    if (params.calendarName !== undefined) {
      if (typeof params.calendarName !== 'string') {
        throw new Error('Calendar name must be a string');
      }

      if (params.calendarName.length > MAX_CALENDAR_NAME_LENGTH) {
        throw new Error(
          `Calendar name too long (max ${MAX_CALENDAR_NAME_LENGTH} characters, got ${params.calendarName.length})`
        );
      }

      // Additional sanitization will be done by sanitizeCalendarName in jxa-generator
      // This is defense-in-depth validation
    }
  }

  /**
   * Execute a predefined query against Calendar.app
   */
  async executeQuery(params: QueryParams): Promise<CalendarEvent[]> {
    // Validate parameters first (defense in depth)
    this.validateParams(params);

    const jxaScript = this.generateJXAScript(params);
    const result = await this.executeJXA(jxaScript);
    
    // Parse JSON with error handling
    try {
      const parsed = JSON.parse(result);
      
      // Validate that we got an array
      if (!Array.isArray(parsed)) {
        throw new Error('Expected array of calendar events');
      }
      
      return parsed;
    } catch (error) {
      if (error instanceof SyntaxError) {
        throw new Error(`Failed to parse Calendar.app response as JSON: ${error.message}`);
      }
      throw error;
    }
  }

  /**
   * Generate JXA script for query
   */
  generateJXAScript(params: QueryParams): string {
    return generateJXAScript(params);
  }

  /**
   * Get filter date based on time range
   */
  getFilterDate(timeRange: string, now: Date): Date {
    return getFilterDate(timeRange, now);
  }

  /**
   * Execute JXA script via osascript
   * Note: Public for testing purposes
   */
  async executeJXA(script: string): Promise<string> {
    return new Promise((resolve, reject) => {
      execFile(
        'osascript',
        ['-l', 'JavaScript', '-e', script],
        { timeout: 30000 },
        (error, stdout, stderr) => {
          if (error) {
            // Check for timeout
            if ((error as any).killed && (error as any).signal === 'SIGTERM') {
              reject(new Error('JXA execution timeout (exceeded 30 seconds)'));
            } else {
              reject(new Error(`JXA execution failed: ${stderr || error.message}`));
            }
          } else {
            resolve(stdout.trim());
          }
        }
      );
    });
  }
}
