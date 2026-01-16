/**
 * Permission System
 *
 * Exports the permission classification system for MCP tools.
 */

export { PermissionClassifier, defaultClassifier } from './permission-classifier.js';
export { PermissionChecker } from './permission-checker.js';
export type {
  SafetyLevel,
  ClassificationResult,
  ClassificationRule,
  PermissionDecision,
  PermissionAuditEntry,
} from './types.js';
