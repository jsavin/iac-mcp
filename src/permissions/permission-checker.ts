/**
 * Permission Checker
 *
 * Manages permission decisions for MCP tool execution. Decides whether to allow,
 * block, or prompt for user confirmation based on safety classification and
 * stored user preferences.
 *
 * Reference: planning/WEEK-3-EXECUTION-LAYER.md (lines 193-267)
 */

import type { MCPTool } from '../types/mcp-tool.js';
import type { PermissionDecision, PermissionAuditEntry, SafetyLevel } from './types.js';
import { PermissionClassifier } from './permission-classifier.js';

/**
 * User preference for a command (per bundleId:commandName key)
 */
interface UserPreference {
  alwaysAllow?: boolean;
  blocked?: boolean;
}

/**
 * Permission Checker
 *
 * Orchestrates permission checking logic:
 * 1. ALWAYS_SAFE → allow: true, prompt: false (no preference needed)
 * 2. ALWAYS_CONFIRM → allow: false, prompt: true (unless user previously allowed)
 * 3. REQUIRES_CONFIRMATION → check preferences; if no preference, ask user
 *
 * Maintains:
 * - In-memory user preferences (bundleId:commandName → decision)
 * - Audit trail of all permission checks
 */
export class PermissionChecker {
  private classifier: PermissionClassifier;
  private preferences: Map<string, UserPreference> = new Map();
  private auditLog: PermissionAuditEntry[] = [];

  /**
   * Last tool checked (for preference tracking and audit logging)
   * Used to maintain state between check() and recordDecision()
   */
  private lastCheckedTool?: MCPTool;
  private lastCheckedArgs: Record<string, any> = {};

  /**
   * Pending preference to be applied to next check()
   * Used when recordDecision() is called before check()
   */
  private pendingPreference?: UserPreference;
  private pendingDecision?: PermissionDecision;

  constructor() {
    this.classifier = new PermissionClassifier();
  }

  /**
   * Check if command should be allowed
   *
   * Decision logic:
   * - ALWAYS_SAFE: Always allow, no prompt
   * - ALWAYS_CONFIRM: Block by default, allow only if user previously granted permission
   * - REQUIRES_CONFIRMATION: Check saved preference, prompt if unknown
   *
   * @param tool - MCP tool definition
   * @param args - Command arguments
   * @returns Permission decision
   */
  async check(tool: MCPTool, args: Record<string, any>): Promise<PermissionDecision> {
    // Store tool and args for recordDecision() to reference
    this.lastCheckedTool = tool;
    this.lastCheckedArgs = args;

    // If there's a pending preference from a prior recordDecision() call,
    // apply it and store it for this tool
    if (this.pendingPreference) {
      const key = this.makePreferenceKey(tool);
      this.preferences.set(key, this.pendingPreference);
      this.pendingPreference = undefined;
    }

    // Classify the command
    const classification = this.classifier.classify(tool, args);

    // Build the decision based on classification
    const decision = this.makeDecision(tool, args, classification.level, classification.reason);

    // Record in audit log
    this.auditLog.push({
      timestamp: new Date(),
      tool: tool.name,
      args,
      decision,
      executed: false,
    });

    return decision;
  }

  /**
   * Record a user decision for future reference
   *
   * Stores user preferences so future checks for the same command
   * don't need to prompt again. Can be called after check() to record
   * user's response, or independently to store preferences that will
   * be applied to the next check() call.
   *
   * @param decision - The decision with user's choice
   */
  async recordDecision(decision: PermissionDecision): Promise<void> {
    // If we have a last checked tool, use it to store preferences and update audit log
    if (this.lastCheckedTool) {
      const key = this.makePreferenceKey(this.lastCheckedTool);

      // Store preference based on the decision
      const preference: UserPreference = {};

      if (decision.alwaysAllow === true) {
        preference.alwaysAllow = true;
      } else if (decision.alwaysAllow === false && !decision.allowed) {
        preference.blocked = true;
      }

      // Store if there's a meaningful preference
      if (preference.alwaysAllow !== undefined || preference.blocked !== undefined) {
        this.preferences.set(key, preference);
      }

      // Update the last audit log entry with this decision if possible
      if (this.auditLog.length > 0) {
        const lastEntry = this.auditLog[this.auditLog.length - 1];
        if (lastEntry.tool === this.lastCheckedTool.name) {
          lastEntry.decision = decision;
        }
      }
    } else {
      // If no tool context, store as pending preference for next check()
      // Build preference from decision
      const preference: UserPreference = {};

      if (decision.alwaysAllow === true) {
        preference.alwaysAllow = true;
      } else if (decision.alwaysAllow === false && !decision.allowed) {
        preference.blocked = true;
      }

      // Store preference for next check() call
      if (preference.alwaysAllow !== undefined || preference.blocked !== undefined) {
        this.pendingPreference = preference;
      }

      // Also record to audit log for visibility
      this.auditLog.push({
        timestamp: new Date(),
        tool: 'unknown',
        args: {},
        decision,
        executed: false,
      });
    }
  }

  /**
   * Get audit log
   *
   * Returns the complete audit trail of permission decisions.
   *
   * @returns Array of audit entries
   */
  getAuditLog(): PermissionAuditEntry[] {
    return this.auditLog;
  }

  /**
   * Make a permission decision based on safety level
   *
   * @param tool - MCP tool
   * @param args - Command arguments
   * @param level - Safety level from classifier
   * @param reason - Reason from classifier
   * @returns Permission decision
   */
  private makeDecision(
    tool: MCPTool,
    args: Record<string, any>,
    level: SafetyLevel,
    reason: string
  ): PermissionDecision {
    switch (level) {
      case 'ALWAYS_SAFE':
        // Always allow, no prompt needed
        return {
          allowed: true,
          level,
          reason,
          requiresPrompt: false,
        };

      case 'ALWAYS_CONFIRM':
        // Check if user has previously granted permission
        const preference = this.getPreference(tool);
        if (preference?.alwaysAllow === true) {
          return {
            allowed: true,
            level,
            reason,
            requiresPrompt: false,
            alwaysAllow: true,
          };
        }

        // If blocked, stay blocked
        if (preference?.blocked === true) {
          return {
            allowed: false,
            level,
            reason,
            requiresPrompt: false,
            alwaysAllow: false,
          };
        }

        // No preference, prompt user
        return {
          allowed: false,
          level,
          reason,
          requiresPrompt: true,
        };

      case 'REQUIRES_CONFIRMATION':
        // Check saved preference
        const savedPreference = this.getPreference(tool);

        if (savedPreference?.alwaysAllow === true) {
          return {
            allowed: true,
            level,
            reason,
            requiresPrompt: false,
            alwaysAllow: true,
          };
        }

        if (savedPreference?.blocked === true) {
          return {
            allowed: false,
            level,
            reason,
            requiresPrompt: false,
            alwaysAllow: false,
          };
        }

        // No preference, require prompt
        return {
          allowed: false,
          level,
          reason,
          requiresPrompt: true,
        };

      default:
        // Unknown level, treat conservatively
        return {
          allowed: false,
          level,
          reason,
          requiresPrompt: true,
        };
    }
  }

  /**
   * Get preference for a tool
   *
   * Looks up saved user preferences for a specific tool command.
   * Preference key format: {bundleId}:{commandName}
   *
   * @param tool - MCP tool
   * @returns Preference if found, undefined otherwise
   */
  private getPreference(tool: MCPTool): UserPreference | undefined {
    const key = this.makePreferenceKey(tool);
    return this.preferences.get(key);
  }

  /**
   * Make preference key from tool
   *
   * Format: {bundleId}:{commandName}
   *
   * @param tool - MCP tool
   * @returns Preference key
   */
  private makePreferenceKey(tool: MCPTool): string {
    const bundleId = tool._metadata?.bundleId || 'unknown';
    const commandName = tool._metadata?.commandName || tool.name || 'unknown';
    return `${bundleId}:${commandName}`;
  }
}
