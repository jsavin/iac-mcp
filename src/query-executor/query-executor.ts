/**
 * Query executor for Calendar.app
 * Generates and executes JXA scripts to query Calendar events
 */

import { execFile } from 'child_process';
import { QueryParams, CalendarEvent } from './types.js';
import { generateJXAScript, getFilterDate } from './jxa-generator.js';

/**
 * QueryExecutor class for executing Calendar.app queries
 */
export class QueryExecutor {
  /**
   * Execute a predefined query against Calendar.app
   */
  async executeQuery(params: QueryParams): Promise<CalendarEvent[]> {
    const jxaScript = this.generateJXAScript(params);
    const result = await this.executeJXA(jxaScript);
    return JSON.parse(result);
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
            reject(new Error(`JXA execution failed: ${stderr || error.message}`));
          } else {
            resolve(stdout.trim());
          }
        }
      );
    });
  }
}
