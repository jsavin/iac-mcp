/**
 * Permission System Type Definitions
 *
 * Defines types used by the permission classification and checking system.
 */

/**
 * Permission safety level
 *
 * Categorizes commands into three safety categories:
 * - ALWAYS_SAFE: Read-only operations with no side effects
 * - REQUIRES_CONFIRMATION: Modifying operations that can be undone
 * - ALWAYS_CONFIRM: Destructive operations that cannot be easily undone
 */
export type SafetyLevel = 'ALWAYS_SAFE' | 'REQUIRES_CONFIRMATION' | 'ALWAYS_CONFIRM';

/**
 * Classification result
 *
 * Result of classifying a command's permission level
 */
export interface ClassificationResult {
  /**
   * Safety level classification
   */
  level: SafetyLevel;

  /**
   * Human-readable reason for the classification
   */
  reason: string;
}

/**
 * Classification rule
 *
 * A custom rule for classifying command permissions
 */
export interface ClassificationRule {
  /**
   * Match condition - returns true if rule applies
   */
  matcher: (tool: any, args?: Record<string, any>) => boolean;

  /**
   * Classification level if rule matches
   */
  level: SafetyLevel;

  /**
   * Reason for classification (optional)
   */
  reason: string;

  /**
   * Priority for rule evaluation (higher = checked first)
   * Default: 100 if not specified
   */
  priority?: number;
}

/**
 * Permission decision
 *
 * Result of checking if a command should be allowed
 */
export interface PermissionDecision {
  /**
   * Whether command is allowed
   */
  allowed: boolean;

  /**
   * Safety level of the command
   */
  level: SafetyLevel;

  /**
   * Human-readable reason
   */
  reason: string;

  /**
   * Whether user needs to confirm
   */
  requiresPrompt: boolean;

  /**
   * User chose "always allow" for this operation
   */
  alwaysAllow?: boolean;
}

/**
 * Permission audit entry
 *
 * Log entry tracking a command execution decision
 */
export interface PermissionAuditEntry {
  /**
   * Timestamp of decision
   */
  timestamp: Date;

  /**
   * Tool name
   */
  tool: string;

  /**
   * Command arguments
   */
  args: Record<string, any>;

  /**
   * Permission decision made
   */
  decision: PermissionDecision;

  /**
   * Whether command was actually executed
   */
  executed: boolean;

  /**
   * Result if executed
   */
  result?: any;

  /**
   * Error if execution failed
   */
  error?: string;
}
