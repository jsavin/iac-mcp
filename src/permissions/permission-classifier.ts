/**
 * Permission Classifier
 *
 * Classifies MCP tool commands into permission levels (ALWAYS_SAFE, REQUIRES_CONFIRMATION, ALWAYS_CONFIRM)
 * based on command patterns and app-specific rules.
 *
 * Reference: planning/WEEK-3-EXECUTION-LAYER.md (lines 123-191)
 */

import type { MCPTool } from '../types/mcp-tool.js';
import type { ClassificationResult, ClassificationRule } from './types.js';

/**
 * Permission Classifier
 *
 * Classifies commands into three safety levels:
 * - ALWAYS_SAFE: Read-only operations (get, list, count, find, search, check)
 * - REQUIRES_CONFIRMATION: Modifying operations (set, make, create, open, save, send, navigate)
 * - ALWAYS_CONFIRM: Destructive/dangerous operations (delete, remove, quit, run, execute, erase, trash)
 */
export class PermissionClassifier {
  private customRules: ClassificationRule[] = [];

  /**
   * Keywords that indicate ALWAYS_SAFE operations (read-only)
   */
  private readonly safePrefixes = [
    'get',
    'list',
    'count',
    'check',
    'find',
    'search',
  ];

  /**
   * Keywords that indicate REQUIRES_CONFIRMATION operations (modifying)
   */
  private readonly modifyPrefixes = [
    'set',
    'make',
    'create',
    'open',
    'save',
    'send',
    'navigate',
    'post',
    'move',
    'copy',
    'duplicate',
    'export',
    'mark',
  ];

  /**
   * Keywords that indicate ALWAYS_CONFIRM operations (destructive/dangerous)
   */
  private readonly dangerousPrefixes = [
    'delete',
    'remove',
    'quit',
    'run',
    'execute',
    'erase',
    'trash',
    'empty',
    'clear',
    'restart',
    'shutdown',
  ];

  /**
   * App-specific safe operations (can override dangerous keywords)
   */
  private readonly appSafeOps: Record<string, string[]> = {
    Finder: ['open_folder'],
  };

  /**
   * Classify a tool command into a safety level
   *
   * @param tool - The MCP tool to classify
   * @param args - Command arguments (optional, for advanced classification)
   * @returns Classification result with level and reason
   */
  classify(tool: MCPTool, args: Record<string, any> = {}): ClassificationResult {
    // Check custom rules first (highest priority)
    for (const rule of this.customRules) {
      if (rule.matcher(tool, args)) {
        return {
          level: rule.level,
          reason: rule.reason,
        };
      }
    }

    // Check app-specific rules
    const appResult = this.classifyAppSpecific(tool, args);
    if (appResult) {
      return appResult;
    }

    // Check command name for keywords
    const keywordResult = this.classifyByKeyword(tool);
    if (keywordResult) {
      return keywordResult;
    }

    // Default to conservative REQUIRES_CONFIRMATION for unknown commands
    return {
      level: 'REQUIRES_CONFIRMATION',
      reason: 'Unknown command - unknown operations require confirmation for safety',
    };
  }

  /**
   * Register a custom classification rule
   *
   * Custom rules are checked first and can override default classification.
   *
   * @param rule - The custom rule to register
   */
  registerRule(rule: ClassificationRule): void {
    this.customRules.push(rule);
  }

  /**
   * Classify based on app-specific rules
   *
   * Some apps have special handling for certain operations.
   * For example, Finder's open_folder is safe, even though "open" normally requires confirmation.
   *
   * @param tool - The MCP tool to classify
   * @param _args - Command arguments (reserved for future use)
   * @returns Classification result if app-specific rule applies, otherwise undefined
   */
  private classifyAppSpecific(
    tool: MCPTool,
    _args: Record<string, any>
  ): ClassificationResult | undefined {
    const appName = tool._metadata?.appName;
    const commandName = tool._metadata?.commandName;

    if (!appName || !commandName) {
      return undefined;
    }

    // Finder: open_folder is safe
    if (appName === 'Finder' && this.appSafeOps.Finder?.includes(commandName)) {
      return {
        level: 'ALWAYS_SAFE',
        reason: `Finder: ${commandName} is a read-only operation`,
      };
    }

    // Finder: delete is dangerous
    if (appName === 'Finder' && commandName === 'delete') {
      return {
        level: 'ALWAYS_CONFIRM',
        reason: `Finder: ${commandName} is a destructive operation`,
      };
    }

    // Mail: get_messages is always safe (read-only)
    if (appName === 'Mail' && commandName === 'get_messages') {
      return {
        level: 'ALWAYS_SAFE',
        reason: 'Mail: Reading messages is a safe operation',
      };
    }

    // Mail: send_message/send_email requires confirmation
    if (
      appName === 'Mail' &&
      (commandName === 'send_message' || commandName === 'send_email')
    ) {
      return {
        level: 'REQUIRES_CONFIRMATION',
        reason: `Mail: Sending messages requires confirmation`,
      };
    }

    return undefined;
  }

  /**
   * Classify based on command name keywords
   *
   * Looks for dangerous, modify, and safe keywords in the command name.
   * Checks dangerous keywords first (most restrictive), then modify, then safe.
   * For compound names like "backup_and_delete", detects dangerous keywords anywhere.
   *
   * @param tool - The MCP tool to classify
   * @returns Classification result if keyword match found, otherwise undefined
   */
  private classifyByKeyword(tool: MCPTool): ClassificationResult | undefined {
    const commandName = tool._metadata?.commandName || tool.name || '';
    const nameLower = commandName.toLowerCase();

    // Check for dangerous keywords (highest priority - most restrictive)
    // Check both prefix and any occurrence in compound names
    for (const keyword of this.dangerousPrefixes) {
      if (
        this.hasKeywordPrefix(commandName, nameLower, keyword) ||
        this.containsKeyword(nameLower, keyword)
      ) {
        return {
          level: 'ALWAYS_CONFIRM',
          reason: `Destructive operation: '${keyword}' indicates a dangerous or destructive command`,
        };
      }
    }

    // Check for modify keywords
    for (const keyword of this.modifyPrefixes) {
      if (this.hasKeywordPrefix(commandName, nameLower, keyword)) {
        return {
          level: 'REQUIRES_CONFIRMATION',
          reason: `Modifying operation: '${keyword}' indicates a command that modifies data`,
        };
      }
    }

    // Check for safe keywords
    for (const keyword of this.safePrefixes) {
      if (this.hasKeywordPrefix(commandName, nameLower, keyword)) {
        return {
          level: 'ALWAYS_SAFE',
          reason: `Read-only operation: '${keyword}' indicates a safe, read-only command`,
        };
      }
    }

    return undefined;
  }

  /**
   * Check if a command name has a keyword as a prefix
   *
   * Matches:
   * - Prefix with underscore: "get_file" starts with "get_"
   * - Exact match: "get" is exactly the keyword
   * - CamelCase: "getName" starts with "get" followed by uppercase
   *
   * @param originalName - The original command name (e.g., "getName")
   * @param nameLower - The command name in lowercase (e.g., "getname")
   * @param keyword - The keyword to search for (lowercase, e.g., "get")
   * @returns True if the keyword is found as a prefix
   */
  private hasKeywordPrefix(originalName: string, nameLower: string, keyword: string): boolean {
    // Check if name starts with keyword + underscore: "get_file"
    if (nameLower.startsWith(keyword + '_')) {
      return true;
    }

    // Check if name is exactly the keyword: "get"
    if (nameLower === keyword) {
      return true;
    }

    // For compound commands, check if keyword appears at the start
    // This handles camelCase by checking the original name for uppercase after keyword
    if (originalName.length > keyword.length && nameLower.startsWith(keyword)) {
      const afterKeyword = originalName[keyword.length];
      // Check if followed by uppercase letter (camelCase) or underscore
      if (afterKeyword && afterKeyword.match(/[A-Z_]/)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Check if a keyword appears anywhere in the command name as a word
   *
   * Matches compound commands like:
   * - "backup_and_delete" contains "delete" (surrounded by underscore)
   * - "get_delete_status" contains "delete" (surrounded by underscores)
   *
   * @param name - The command name (lowercase)
   * @param keyword - The keyword to search for (lowercase)
   * @returns True if the keyword is found as a complete word
   */
  private containsKeyword(name: string, keyword: string): boolean {
    // Look for keyword surrounded by underscores or at word boundaries
    const patterns = [
      new RegExp(`_${keyword}_`), // Between underscores
      new RegExp(`_${keyword}$`), // At the end after underscore
      new RegExp(`^${keyword}_`), // At the start before underscore
    ];

    for (const pattern of patterns) {
      if (pattern.test(name)) {
        return true;
      }
    }

    return false;
  }
}

/**
 * Create and export a singleton instance
 * Tests can import this or create their own instance
 */
export const defaultClassifier = new PermissionClassifier();
