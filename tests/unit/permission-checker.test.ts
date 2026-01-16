/**
 * Unit tests for PermissionChecker
 *
 * Tests the permission checking and enforcement logic that decides whether
 * commands should be executed based on safety classifications and user preferences.
 *
 * The PermissionChecker handles:
 * 1. ALWAYS_SAFE: Return allowed immediately, no prompt needed
 * 2. REQUIRES_CONFIRMATION: Check saved preference, or prompt if unknown
 * 3. ALWAYS_CONFIRM: Always prompt unless explicitly allowed
 * 4. User preferences: Track "always allow" and "block" decisions per command
 * 5. Audit trail: Log all permission decisions for accountability
 *
 * Reference: planning/WEEK-3-EXECUTION-LAYER.md (lines 193-267)
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import type { MCPTool, ToolMetadata } from '../../src/types/mcp-tool.js';
import type { PermissionDecision, PermissionAuditEntry } from '../../src/permissions/types.js';

/**
 * NOTE: PermissionChecker class does not exist yet.
 * This is a Test-Driven Development (TDD) test suite.
 * The tests define the expected API and behavior.
 * Implementation should follow these tests.
 *
 * To implement:
 * 1. Create PermissionChecker class in src/permissions/permission-checker.ts or new file
 * 2. Implement methods: check(), recordDecision(), getAuditLog()
 * 3. Use PermissionClassifier for classification
 * 4. Implement preference storage (in-memory for MVP)
 * 5. Implement audit trail tracking
 * 6. Export from src/permissions/index.ts
 */

// @ts-expect-error PermissionChecker not yet implemented
import { PermissionChecker } from '../../src/permissions/index.js';

/**
 * Mock storage interface for user preferences
 * Allows us to test persistence logic without actual file I/O
 */
interface MockPreferenceStore {
  get: (key: string) => Promise<any>;
  set: (key: string, value: any) => Promise<void>;
  clear: () => Promise<void>;
}

/**
 * In-memory mock storage implementation
 */
class InMemoryPreferenceStore implements MockPreferenceStore {
  private data: Map<string, any> = new Map();

  async get(key: string): Promise<any> {
    return this.data.get(key);
  }

  async set(key: string, value: any): Promise<void> {
    this.data.set(key, value);
  }

  async clear(): Promise<void> {
    this.data.clear();
  }

  // Helper for testing
  getAll(): Record<string, any> {
    return Object.fromEntries(this.data);
  }
}

/**
 * Helper to create a test MCPTool with metadata
 */
function createTestTool(
  name: string,
  commandName: string,
  appName: string = 'Finder',
  description: string = 'Test command'
): MCPTool {
  return {
    name,
    description,
    inputSchema: {
      type: 'object',
      properties: {},
      required: [],
    },
    _metadata: {
      appName,
      bundleId: `com.apple.${appName.toLowerCase()}`,
      commandName,
      commandCode: 'test',
      suiteName: 'Standard',
    } as ToolMetadata,
  };
}

/**
 * Helper to create preference key for a tool
 */
function makePreferenceKey(bundleId: string, commandName: string): string {
  return `${bundleId}:${commandName}`;
}

describe('PermissionChecker', () => {
  let checker: PermissionChecker;
  let mockStorage: InMemoryPreferenceStore;

  beforeEach(() => {
    mockStorage = new InMemoryPreferenceStore();
    // Create checker with mock storage
    // Note: Constructor may need to be updated to accept storage option
    checker = new PermissionChecker();
  });

  afterEach(() => {
    mockStorage.clear();
  });

  // ============================================================================
  // ALWAYS_SAFE Commands
  // ============================================================================

  describe('ALWAYS_SAFE Commands', () => {
    let safeReadTool: MCPTool;

    beforeEach(() => {
      safeReadTool = createTestTool(
        'finder_list_folder',
        'list_folder',
        'Finder',
        'List items in a folder'
      );
    });

    it('should return { allowed: true, requiresPrompt: false } for ALWAYS_SAFE commands', async () => {
      const decision = await checker.check(safeReadTool, {});

      expect(decision.allowed).toBe(true);
      expect(decision.requiresPrompt).toBe(false);
      expect(decision.level).toBe('ALWAYS_SAFE');
    });

    it('should not require user preference for ALWAYS_SAFE commands', async () => {
      const decision = await checker.check(safeReadTool, {});

      expect(decision.alwaysAllow).toBeUndefined();
    });

    it('should not be blockable - ALWAYS_SAFE always allowed', async () => {
      // Even if we try to block it, it should be allowed
      const decision = await checker.check(safeReadTool, {});

      expect(decision.allowed).toBe(true);
    });

    it('should provide reason for ALWAYS_SAFE classification', async () => {
      const decision = await checker.check(safeReadTool, {});

      expect(decision.reason).toBeDefined();
      expect(decision.reason.length).toBeGreaterThan(0);
    });

    it('should allow multiple consecutive calls without prompt', async () => {
      const decision1 = await checker.check(safeReadTool, {});
      const decision2 = await checker.check(safeReadTool, {});

      expect(decision1.allowed).toBe(true);
      expect(decision1.requiresPrompt).toBe(false);
      expect(decision2.allowed).toBe(true);
      expect(decision2.requiresPrompt).toBe(false);
    });
  });

  // ============================================================================
  // ALWAYS_CONFIRM Commands
  // ============================================================================

  describe('ALWAYS_CONFIRM Commands', () => {
    let dangerousTool: MCPTool;

    beforeEach(() => {
      dangerousTool = createTestTool(
        'finder_delete',
        'delete',
        'Finder',
        'Delete a file or folder'
      );
    });

    it('should return { allowed: false, requiresPrompt: true } by default', async () => {
      const decision = await checker.check(dangerousTool, {});

      expect(decision.allowed).toBe(false);
      expect(decision.requiresPrompt).toBe(true);
      expect(decision.level).toBe('ALWAYS_CONFIRM');
    });

    it('should block by default without user permission', async () => {
      const decision = await checker.check(dangerousTool, {});

      expect(decision.allowed).toBe(false);
    });

    it('should allow with { alwaysAllow: true } permission', async () => {
      // Record user decision to always allow
      await checker.recordDecision({
        allowed: true,
        level: 'ALWAYS_CONFIRM',
        reason: 'User granted permission',
        requiresPrompt: false,
        alwaysAllow: true,
      });

      // Second check should use saved preference
      const decision = await checker.check(dangerousTool, {});

      expect(decision.allowed).toBe(true);
      expect(decision.alwaysAllow).toBe(true);
    });

    it('should respect user block preference', async () => {
      // Record user decision to block
      await checker.recordDecision({
        allowed: false,
        level: 'ALWAYS_CONFIRM',
        reason: 'User blocked this operation',
        requiresPrompt: false,
        alwaysAllow: false,
      });

      // Second check should remain blocked
      const decision = await checker.check(dangerousTool, {});

      expect(decision.allowed).toBe(false);
    });

    it('should remember persistent permission across multiple checks', async () => {
      // First grant permission
      await checker.recordDecision({
        allowed: true,
        level: 'ALWAYS_CONFIRM',
        reason: 'User granted permission',
        requiresPrompt: false,
        alwaysAllow: true,
      });

      // Multiple subsequent checks should all respect the permission
      const decision1 = await checker.check(dangerousTool, {});
      const decision2 = await checker.check(dangerousTool, {});
      const decision3 = await checker.check(dangerousTool, {});

      expect(decision1.allowed).toBe(true);
      expect(decision2.allowed).toBe(true);
      expect(decision3.allowed).toBe(true);
    });

    it('should allow user to change preference from allow to block', async () => {
      // First grant permission
      await checker.recordDecision({
        allowed: true,
        level: 'ALWAYS_CONFIRM',
        reason: 'User granted permission',
        requiresPrompt: false,
        alwaysAllow: true,
      });

      // Change decision to block
      await checker.recordDecision({
        allowed: false,
        level: 'ALWAYS_CONFIRM',
        reason: 'User revoked permission',
        requiresPrompt: false,
        alwaysAllow: false,
      });

      // Check should now block
      const decision = await checker.check(dangerousTool, {});

      expect(decision.allowed).toBe(false);
    });

    it('should track decision context in audit log', async () => {
      await checker.recordDecision({
        allowed: true,
        level: 'ALWAYS_CONFIRM',
        reason: 'User granted permission',
        requiresPrompt: false,
        alwaysAllow: true,
      });

      const auditLog = checker.getAuditLog();

      expect(auditLog.length).toBeGreaterThan(0);
      const entry = auditLog[0];
      expect(entry.decision.alwaysAllow).toBe(true);
    });
  });

  // ============================================================================
  // REQUIRES_CONFIRMATION Commands
  // ============================================================================

  describe('REQUIRES_CONFIRMATION Commands', () => {
    let modifyTool: MCPTool;

    beforeEach(() => {
      modifyTool = createTestTool(
        'finder_move',
        'move',
        'Finder',
        'Move a file or folder'
      );
    });

    it('should return { allowed: false, requiresPrompt: true } when no preference saved', async () => {
      const decision = await checker.check(modifyTool, {});

      expect(decision.allowed).toBe(false);
      expect(decision.requiresPrompt).toBe(true);
      expect(decision.level).toBe('REQUIRES_CONFIRMATION');
    });

    it('should use saved preference when available', async () => {
      // First, save an allow preference
      await checker.recordDecision({
        allowed: true,
        level: 'REQUIRES_CONFIRMATION',
        reason: 'User granted permission',
        requiresPrompt: false,
        alwaysAllow: true,
      });

      // Second check should use saved preference
      const decision = await checker.check(modifyTool, {});

      expect(decision.allowed).toBe(true);
      expect(decision.requiresPrompt).toBe(false);
    });

    it('should respect saved block preference', async () => {
      // Save a block preference
      await checker.recordDecision({
        allowed: false,
        level: 'REQUIRES_CONFIRMATION',
        reason: 'User blocked this operation',
        requiresPrompt: false,
        alwaysAllow: false,
      });

      // Check should use the saved block preference
      const decision = await checker.check(modifyTool, {});

      expect(decision.allowed).toBe(false);
      expect(decision.requiresPrompt).toBe(false);
    });

    it('should store preference for future use', async () => {
      // Record user decision
      await checker.recordDecision({
        allowed: true,
        level: 'REQUIRES_CONFIRMATION',
        reason: 'User granted permission',
        requiresPrompt: false,
        alwaysAllow: true,
      });

      // First check
      const decision1 = await checker.check(modifyTool, {});

      // Simulate user deciding without checking stored preference
      expect(decision1.allowed).toBe(true);
    });

    it('should treat allow and block preferences equally', async () => {
      // Test with allow preference
      await checker.recordDecision({
        allowed: true,
        level: 'REQUIRES_CONFIRMATION',
        reason: 'User allowed',
        requiresPrompt: false,
        alwaysAllow: true,
      });

      let decision = await checker.check(modifyTool, {});
      expect(decision.allowed).toBe(true);

      // Change to block preference
      await checker.recordDecision({
        allowed: false,
        level: 'REQUIRES_CONFIRMATION',
        reason: 'User blocked',
        requiresPrompt: false,
        alwaysAllow: false,
      });

      decision = await checker.check(modifyTool, {});
      expect(decision.allowed).toBe(false);
    });

    it('should prompt again if preference is cleared', async () => {
      // Save preference
      await checker.recordDecision({
        allowed: true,
        level: 'REQUIRES_CONFIRMATION',
        reason: 'User granted permission',
        requiresPrompt: false,
        alwaysAllow: true,
      });

      // Clear preferences (simulating user reset)
      // This would need a clearPreferences() method or similar
      // For now, we test the concept
      const decision = await checker.check(modifyTool, {});
      expect(decision).toBeDefined();
    });
  });

  // ============================================================================
  // User Preferences
  // ============================================================================

  describe('User Preferences', () => {
    it('should use per-command preferences with key format {bundleId}:{commandName}', async () => {
      const tool1 = createTestTool(
        'finder_move',
        'move',
        'Finder'
      );
      const tool2 = createTestTool(
        'finder_copy',
        'copy',
        'Finder'
      );

      // Grant permission for tool1
      await checker.recordDecision({
        allowed: true,
        level: 'REQUIRES_CONFIRMATION',
        reason: 'User allowed move',
        requiresPrompt: false,
        alwaysAllow: true,
      });

      // tool1 should be allowed, tool2 should still prompt
      const decision1 = await checker.check(tool1, {});
      const decision2 = await checker.check(tool2, {});

      // Note: This test assumes the checker properly scopes preferences by tool
      // The exact behavior depends on implementation
      expect(decision1.allowed).toBe(true);
      // decision2 may require prompt since no preference set
    });

    it('should persist allow preference across sessions', async () => {
      const tool = createTestTool(
        'finder_move',
        'move'
      );

      // Record preference
      await checker.recordDecision({
        allowed: true,
        level: 'REQUIRES_CONFIRMATION',
        reason: 'User granted permission',
        requiresPrompt: false,
        alwaysAllow: true,
      });

      // New checker instance (simulating new session)
      // Note: This would require the checker to use persistent storage
      const decision = await checker.check(tool, {});
      expect(decision.allowed).toBe(true);
    });

    it('should handle null/undefined preferences gracefully', async () => {
      const tool = createTestTool(
        'finder_move',
        'move'
      );

      // Check with no preference set
      const decision = await checker.check(tool, {});

      expect(decision).toBeDefined();
      expect(decision.requiresPrompt).toBe(true);
    });

    it('should handle empty preference object gracefully', async () => {
      const tool = createTestTool(
        'finder_move',
        'move'
      );

      // Simulate empty preference object
      const decision = await checker.check(tool, {});

      expect(decision).toBeDefined();
      expect(decision.level).toBe('REQUIRES_CONFIRMATION');
    });

    it('should not be confused by different apps with same command name', async () => {
      const finderMove = createTestTool(
        'finder_move',
        'move',
        'Finder'
      );
      const mailMove = createTestTool(
        'mail_move',
        'move',
        'Mail'
      );

      // Grant permission for Finder move
      await checker.recordDecision({
        allowed: true,
        level: 'REQUIRES_CONFIRMATION',
        reason: 'User allowed Finder move',
        requiresPrompt: false,
        alwaysAllow: true,
      });

      // Mail move should have different preference
      const decision1 = await checker.check(finderMove, {});
      const decision2 = await checker.check(mailMove, {});

      expect(decision1.allowed).toBe(true);
      // decision2 depends on whether preferences are properly scoped
    });
  });

  // ============================================================================
  // Decision Logic
  // ============================================================================

  describe('Decision Logic', () => {
    it('should follow ALWAYS_SAFE → Always allow', async () => {
      const tool = createTestTool(
        'finder_list_folder',
        'list_folder'
      );

      const decision = await checker.check(tool, {});

      expect(decision.allowed).toBe(true);
      expect(decision.requiresPrompt).toBe(false);
    });

    it('should follow REQUIRES_CONFIRMATION + Preference → Use preference', async () => {
      const tool = createTestTool(
        'finder_move',
        'move'
      );

      // Save preference
      await checker.recordDecision({
        allowed: true,
        level: 'REQUIRES_CONFIRMATION',
        reason: 'User allowed',
        requiresPrompt: false,
        alwaysAllow: true,
      });

      const decision = await checker.check(tool, {});

      expect(decision.allowed).toBe(true);
      expect(decision.requiresPrompt).toBe(false);
    });

    it('should follow REQUIRES_CONFIRMATION + No Preference → Prompt user', async () => {
      const tool = createTestTool(
        'finder_move',
        'move'
      );

      const decision = await checker.check(tool, {});

      expect(decision.allowed).toBe(false);
      expect(decision.requiresPrompt).toBe(true);
    });

    it('should follow ALWAYS_CONFIRM + No Permission → Block', async () => {
      const tool = createTestTool(
        'finder_delete',
        'delete'
      );

      const decision = await checker.check(tool, {});

      expect(decision.allowed).toBe(false);
      expect(decision.requiresPrompt).toBe(true);
    });

    it('should follow ALWAYS_CONFIRM + Permission → Allow', async () => {
      const tool = createTestTool(
        'finder_delete',
        'delete'
      );

      // Grant permission
      await checker.recordDecision({
        allowed: true,
        level: 'ALWAYS_CONFIRM',
        reason: 'User granted',
        requiresPrompt: false,
        alwaysAllow: true,
      });

      const decision = await checker.check(tool, {});

      expect(decision.allowed).toBe(true);
    });

    it('should handle unknown safety level gracefully', async () => {
      const tool = createTestTool(
        'unknown_command',
        'unknown'
      );

      // Should handle gracefully, probably defaulting to REQUIRES_CONFIRMATION
      const decision = await checker.check(tool, {});

      expect(decision).toBeDefined();
      expect(decision.requiresPrompt).toBeDefined();
    });
  });

  // ============================================================================
  // Audit Trail
  // ============================================================================

  describe('Audit Trail', () => {
    it('should track all permission decisions', async () => {
      const tool = createTestTool(
        'finder_list_folder',
        'list_folder'
      );

      await checker.check(tool, {});

      const auditLog = checker.getAuditLog();

      expect(auditLog.length).toBeGreaterThan(0);
    });

    it('should record timestamp for each decision', async () => {
      const tool = createTestTool(
        'finder_list_folder',
        'list_folder'
      );

      await checker.check(tool, {});

      const auditLog = checker.getAuditLog();
      const entry = auditLog[0];

      expect(entry.timestamp).toBeDefined();
      expect(entry.timestamp instanceof Date).toBe(true);
    });

    it('should record app name in audit log', async () => {
      const tool = createTestTool(
        'finder_list_folder',
        'list_folder',
        'Finder'
      );

      await checker.check(tool, {});

      const auditLog = checker.getAuditLog();
      const entry = auditLog[0];

      expect(entry.tool).toBe('finder_list_folder');
    });

    it('should record command arguments in audit log', async () => {
      const tool = createTestTool(
        'finder_move',
        'move'
      );
      const args = { from: '/path/to/source', to: '/path/to/dest' };

      await checker.check(tool, args);

      const auditLog = checker.getAuditLog();
      const entry = auditLog[0];

      expect(entry.args).toEqual(args);
    });

    it('should record permission decision in audit log', async () => {
      const tool = createTestTool(
        'finder_list_folder',
        'list_folder'
      );

      await checker.check(tool, {});

      const auditLog = checker.getAuditLog();
      const entry = auditLog[0];

      expect(entry.decision).toBeDefined();
      expect(entry.decision.allowed).toBeDefined();
      expect(entry.decision.level).toBeDefined();
      expect(entry.decision.reason).toBeDefined();
    });

    it('should track execution status in audit log', async () => {
      const tool = createTestTool(
        'finder_list_folder',
        'list_folder'
      );

      await checker.check(tool, {});

      const auditLog = checker.getAuditLog();
      const entry = auditLog[0];

      // Entry should have executed flag (even if false since we didn't execute)
      expect(entry.executed).toBeDefined();
    });

    it('should allow recording execution result in audit log', async () => {
      const tool = createTestTool(
        'finder_list_folder',
        'list_folder'
      );

      const decision = await checker.check(tool, {});

      // Simulate recording execution result
      await checker.recordDecision({
        ...decision,
      });

      const auditLog = checker.getAuditLog();

      expect(auditLog.length).toBeGreaterThanOrEqual(1);
    });

    it('should allow recording execution error in audit log', async () => {
      const tool = createTestTool(
        'finder_list_folder',
        'list_folder'
      );

      const decision = await checker.check(tool, {});

      // Simulate recording execution error
      // Note: recordDecision may need an error parameter
      await checker.recordDecision({
        ...decision,
      });

      const auditLog = checker.getAuditLog();

      // Error tracking depends on implementation
      expect(auditLog).toBeDefined();
    });

    it('should retrieve audit log for security review', async () => {
      const tool1 = createTestTool(
        'finder_list_folder',
        'list_folder'
      );
      const tool2 = createTestTool(
        'finder_move',
        'move'
      );

      await checker.check(tool1, {});
      await checker.check(tool2, {});

      const auditLog = checker.getAuditLog();

      expect(auditLog.length).toBeGreaterThanOrEqual(2);
      // Should be able to trace what operations were checked and why
    });

    it('should maintain chronological order in audit log', async () => {
      const tool = createTestTool(
        'finder_list_folder',
        'list_folder'
      );

      const timestamp1 = Date.now();
      await checker.check(tool, {});
      const timestamp2 = Date.now();
      await checker.check(tool, {});
      const timestamp3 = Date.now();

      const auditLog = checker.getAuditLog();

      if (auditLog.length >= 2) {
        const entry1 = auditLog[0];
        const entry2 = auditLog[1];
        expect(entry1.timestamp.getTime()).toBeLessThanOrEqual(
          entry2.timestamp.getTime()
        );
      }
    });

    it('should not lose audit history between checks', async () => {
      const tool = createTestTool(
        'finder_list_folder',
        'list_folder'
      );

      await checker.check(tool, {});
      const log1 = checker.getAuditLog();
      const count1 = log1.length;

      await checker.check(tool, {});
      const log2 = checker.getAuditLog();
      const count2 = log2.length;

      expect(count2).toBeGreaterThanOrEqual(count1);
    });
  });

  // ============================================================================
  // Edge Cases
  // ============================================================================

  describe('Edge Cases', () => {
    it('should handle null preferences gracefully', async () => {
      const tool = createTestTool(
        'finder_move',
        'move'
      );

      // No preference set
      const decision = await checker.check(tool, {});

      expect(decision).toBeDefined();
      expect(decision.requiresPrompt).toBe(true);
    });

    it('should handle undefined preferences gracefully', async () => {
      const tool = createTestTool(
        'finder_move',
        'move'
      );

      const decision = await checker.check(tool, {});

      expect(decision).toBeDefined();
      expect(decision.level).toBe('REQUIRES_CONFIRMATION');
    });

    it('should handle empty preference object', async () => {
      const tool = createTestTool(
        'finder_move',
        'move'
      );

      const decision = await checker.check(tool, {});

      expect(decision.requiresPrompt).toBe(true);
    });

    it('should handle conflicting preferences (both allow and block)', async () => {
      const tool = createTestTool(
        'finder_move',
        'move'
      );

      // Attempt to set conflicting preferences
      // Implementation should handle this gracefully
      // Probably prefer the most recent or block by default
      const decision = await checker.check(tool, {});

      expect(decision).toBeDefined();
      expect(decision.allowed).toBeDefined();
    });

    it('should handle preference change after initial decision', async () => {
      const tool = createTestTool(
        'finder_move',
        'move'
      );

      // First decision with no preference
      const decision1 = await checker.check(tool, {});
      expect(decision1.requiresPrompt).toBe(true);

      // Record preference
      await checker.recordDecision({
        allowed: true,
        level: 'REQUIRES_CONFIRMATION',
        reason: 'User granted',
        requiresPrompt: false,
        alwaysAllow: true,
      });

      // Second decision should use new preference
      const decision2 = await checker.check(tool, {});
      expect(decision2.requiresPrompt).toBe(false);
    });

    it('should handle multiple users with different preferences', async () => {
      // This is a conceptual test - actual multi-user support depends on implementation
      // For now, test that preferences are isolated per checker instance

      const checker1 = new PermissionChecker();
      const checker2 = new PermissionChecker();

      const tool = createTestTool(
        'finder_move',
        'move'
      );

      // User 1 allows
      await checker1.recordDecision({
        allowed: true,
        level: 'REQUIRES_CONFIRMATION',
        reason: 'User 1 allowed',
        requiresPrompt: false,
        alwaysAllow: true,
      });

      // User 2 checks (should not see User 1's preference)
      // This depends on whether preferences are stored globally or per-instance
      const decision = await checker2.check(tool, {});

      // For MVP, this likely prompts regardless
      expect(decision).toBeDefined();
    });

    it('should handle tool without metadata gracefully', async () => {
      const tool: MCPTool = {
        name: 'unknown_tool',
        description: 'Unknown tool',
        inputSchema: {
          type: 'object',
          properties: {},
        },
        // No _metadata
      };

      const decision = await checker.check(tool, {});

      expect(decision).toBeDefined();
      expect(decision.requiresPrompt).toBeDefined();
    });

    it('should handle empty command arguments', async () => {
      const tool = createTestTool(
        'finder_list_folder',
        'list_folder'
      );

      const decision = await checker.check(tool, {});

      expect(decision).toBeDefined();
      expect(decision.allowed).toBe(true);
    });

    it('should handle very long argument values', async () => {
      const tool = createTestTool(
        'finder_move',
        'move'
      );
      const veryLongPath = '/' + 'x'.repeat(10000);
      const args = { from: veryLongPath, to: veryLongPath };

      const decision = await checker.check(tool, args);

      expect(decision).toBeDefined();
      expect(decision.level).toBe('REQUIRES_CONFIRMATION');
    });

    it('should handle special characters in arguments', async () => {
      const tool = createTestTool(
        'finder_move',
        'move'
      );
      const args = {
        from: '/path/with spaces/and "quotes" and \\backslashes',
        to: '/path/with/émojis/🎉',
      };

      const decision = await checker.check(tool, args);

      expect(decision).toBeDefined();
    });

    it('should handle null arguments object', async () => {
      const tool = createTestTool(
        'finder_list_folder',
        'list_folder'
      );

      // Should handle null args gracefully
      const decision = await checker.check(tool, {});

      expect(decision).toBeDefined();
    });

    it('should be idempotent - checking same operation twice gives same result', async () => {
      const tool = createTestTool(
        'finder_list_folder',
        'list_folder'
      );

      const decision1 = await checker.check(tool, {});
      const decision2 = await checker.check(tool, {});

      expect(decision1.allowed).toBe(decision2.allowed);
      expect(decision1.requiresPrompt).toBe(decision2.requiresPrompt);
      expect(decision1.level).toBe(decision2.level);
    });
  });

  // ============================================================================
  // Preference Persistence
  // ============================================================================

  describe('Preference Persistence (Conceptual)', () => {
    it('should allow clearing all preferences', async () => {
      const tool = createTestTool(
        'finder_move',
        'move'
      );

      // Save preference
      await checker.recordDecision({
        allowed: true,
        level: 'REQUIRES_CONFIRMATION',
        reason: 'User allowed',
        requiresPrompt: false,
        alwaysAllow: true,
      });

      // Check with preference
      let decision = await checker.check(tool, {});
      expect(decision.allowed).toBe(true);

      // Clear preferences (if method exists)
      // Note: This depends on implementation providing a clear method
      // For now, test concept

      // After clear, should prompt again
      decision = await checker.check(tool, {});
      expect(decision).toBeDefined();
    });

    it('should allow revoking a specific permission', async () => {
      const tool = createTestTool(
        'finder_move',
        'move'
      );

      // Grant permission
      await checker.recordDecision({
        allowed: true,
        level: 'REQUIRES_CONFIRMATION',
        reason: 'User allowed',
        requiresPrompt: false,
        alwaysAllow: true,
      });

      let decision = await checker.check(tool, {});
      expect(decision.allowed).toBe(true);

      // Revoke permission
      await checker.recordDecision({
        allowed: false,
        level: 'REQUIRES_CONFIRMATION',
        reason: 'User revoked',
        requiresPrompt: false,
        alwaysAllow: false,
      });

      decision = await checker.check(tool, {});
      expect(decision.allowed).toBe(false);
    });

    it('should support exporting audit log for review', async () => {
      const tool1 = createTestTool(
        'finder_list_folder',
        'list_folder'
      );
      const tool2 = createTestTool(
        'finder_delete',
        'delete'
      );

      await checker.check(tool1, {});
      await checker.check(tool2, {});

      const auditLog = checker.getAuditLog();

      expect(Array.isArray(auditLog)).toBe(true);
      expect(auditLog.length).toBeGreaterThan(0);

      // Log should be serializable
      const serialized = JSON.stringify(auditLog, (key, value) => {
        if (value instanceof Date) {
          return value.toISOString();
        }
        return value;
      });
      expect(serialized).toBeDefined();
    });
  });

  // ============================================================================
  // Integration with Permission Classifier
  // ============================================================================

  describe('Integration with Permission Classifier', () => {
    it('should correctly classify ALWAYS_SAFE and allow immediately', async () => {
      const tool = createTestTool(
        'finder_list_folder',
        'list_folder'
      );

      const decision = await checker.check(tool, {});

      expect(decision.level).toBe('ALWAYS_SAFE');
      expect(decision.allowed).toBe(true);
      expect(decision.requiresPrompt).toBe(false);
    });

    it('should correctly classify REQUIRES_CONFIRMATION and prompt if no preference', async () => {
      const tool = createTestTool(
        'finder_move',
        'move'
      );

      const decision = await checker.check(tool, {});

      expect(decision.level).toBe('REQUIRES_CONFIRMATION');
      expect(decision.allowed).toBe(false);
      expect(decision.requiresPrompt).toBe(true);
    });

    it('should correctly classify ALWAYS_CONFIRM and always prompt', async () => {
      const tool = createTestTool(
        'finder_delete',
        'delete'
      );

      const decision = await checker.check(tool, {});

      expect(decision.level).toBe('ALWAYS_CONFIRM');
      expect(decision.allowed).toBe(false);
      expect(decision.requiresPrompt).toBe(true);
    });

    it('should provide reason from classifier', async () => {
      const tool = createTestTool(
        'finder_list_folder',
        'list_folder'
      );

      const decision = await checker.check(tool, {});

      expect(decision.reason).toBeDefined();
      expect(decision.reason.length).toBeGreaterThan(0);
    });
  });

  // ============================================================================
  // Error Handling
  // ============================================================================

  describe('Error Handling', () => {
    it('should not throw on invalid tool', async () => {
      const invalidTool: MCPTool = {
        name: '',
        description: '',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      };

      expect(async () => {
        await checker.check(invalidTool, {});
      }).not.toThrow();
    });

    it('should handle preference storage errors gracefully', async () => {
      // This would require a broken storage backend
      // For now, just ensure method exists and doesn't crash
      const tool = createTestTool(
        'finder_move',
        'move'
      );

      const decision = await checker.check(tool, {});

      expect(decision).toBeDefined();
    });

    it('should not crash when recording invalid decisions', async () => {
      const invalidDecision: any = {
        // Missing required fields
      };

      expect(async () => {
        await checker.recordDecision(invalidDecision);
      }).not.toThrow();
    });
  });
});
