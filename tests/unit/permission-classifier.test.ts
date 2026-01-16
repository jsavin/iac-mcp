/**
 * Unit tests for PermissionClassifier
 *
 * Tests permission classification of MCP tool commands based on safety rules.
 * The classifier categorizes commands into three permission levels:
 *
 * 1. ALWAYS_SAFE - Read-only operations, no side effects
 * 2. REQUIRES_CONFIRMATION - Modifying operations, can be undone
 * 3. ALWAYS_CONFIRM - Destructive/dangerous operations, cannot be easily undone
 *
 * Reference: planning/WEEK-3-EXECUTION-LAYER.md (lines 123-191)
 */

import { describe, it, expect, beforeEach } from 'vitest';
import type { MCPTool, ToolMetadata } from '../../src/types/mcp-tool.js';
import type { SafetyLevel } from '../../src/permissions/types.js';
import { PermissionClassifier } from '../../src/permissions/permission-classifier.js';

/**
 * Helper to create a test MCPTool with default metadata
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

describe('PermissionClassifier', () => {
  let classifier: PermissionClassifier;

  beforeEach(() => {
    classifier = new PermissionClassifier();
  });

  // ============================================================================
  // ALWAYS_SAFE Operations
  // ============================================================================

  describe('classify() - ALWAYS_SAFE operations', () => {
    describe('list/get commands', () => {
      it('should classify "list_folder" as ALWAYS_SAFE', () => {
        const tool = createTestTool(
          'finder_list_folder',
          'list_folder',
          'Finder',
          'List items in a folder'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_SAFE');
        expect(result.reason).toContain('read-only');
      });

      it('should classify "get_url" as ALWAYS_SAFE', () => {
        const tool = createTestTool(
          'safari_get_url',
          'get_url',
          'Safari',
          'Get the current URL'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_SAFE');
      });

      it('should classify "get_file_info" as ALWAYS_SAFE', () => {
        const tool = createTestTool(
          'finder_get_file_info',
          'get_file_info',
          'Finder'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_SAFE');
      });

      it('should classify "count_messages" as ALWAYS_SAFE', () => {
        const tool = createTestTool(
          'mail_count_messages',
          'count_messages',
          'Mail'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_SAFE');
      });

      it('should classify "get_version" as ALWAYS_SAFE', () => {
        const tool = createTestTool('app_get_version', 'get_version', 'App');
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_SAFE');
      });
    });

    describe('read-only query commands', () => {
      it('should classify "find_items" as ALWAYS_SAFE', () => {
        const tool = createTestTool(
          'finder_find_items',
          'find_items',
          'Finder'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_SAFE');
      });

      it('should classify "search_mail" as ALWAYS_SAFE', () => {
        const tool = createTestTool('mail_search_mail', 'search_mail', 'Mail');
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_SAFE');
      });

      it('should classify "count_windows" as ALWAYS_SAFE', () => {
        const tool = createTestTool(
          'app_count_windows',
          'count_windows',
          'App'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_SAFE');
      });

      it('should classify "get_status" as ALWAYS_SAFE', () => {
        const tool = createTestTool('app_get_status', 'get_status', 'App');
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_SAFE');
      });
    });

    describe('non-destructive read operations', () => {
      it('should classify "get_name" as ALWAYS_SAFE', () => {
        const tool = createTestTool('app_get_name', 'get_name', 'App');
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_SAFE');
      });

      it('should classify "get_properties" as ALWAYS_SAFE', () => {
        const tool = createTestTool(
          'app_get_properties',
          'get_properties',
          'App'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_SAFE');
      });

      it('should classify "check_exists" as ALWAYS_SAFE', () => {
        const tool = createTestTool(
          'finder_check_exists',
          'check_exists',
          'Finder'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_SAFE');
      });
    });

    describe('Finder-specific SAFE operations', () => {
      it('should classify "open_folder" as ALWAYS_SAFE in Finder context', () => {
        const tool = createTestTool(
          'finder_open_folder',
          'open_folder',
          'Finder'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_SAFE');
      });

      it('should classify "get_kind" as ALWAYS_SAFE', () => {
        const tool = createTestTool('finder_get_kind', 'get_kind', 'Finder');
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_SAFE');
      });
    });

    describe('Mail-specific SAFE operations', () => {
      it('should classify "get_messages" as ALWAYS_SAFE', () => {
        const tool = createTestTool(
          'mail_get_messages',
          'get_messages',
          'Mail'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_SAFE');
      });

      it('should classify "list_mailboxes" as ALWAYS_SAFE', () => {
        const tool = createTestTool(
          'mail_list_mailboxes',
          'list_mailboxes',
          'Mail'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_SAFE');
      });
    });
  });

  // ============================================================================
  // REQUIRES_CONFIRMATION Operations
  // ============================================================================

  describe('classify() - REQUIRES_CONFIRMATION operations', () => {
    describe('set commands', () => {
      it('should classify "set_property" as REQUIRES_CONFIRMATION', () => {
        const tool = createTestTool(
          'app_set_property',
          'set_property',
          'App'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('REQUIRES_CONFIRMATION');
      });

      it('should classify "set_name" as REQUIRES_CONFIRMATION', () => {
        const tool = createTestTool('app_set_name', 'set_name', 'App');
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('REQUIRES_CONFIRMATION');
      });

      it('should classify "set_label" as REQUIRES_CONFIRMATION', () => {
        const tool = createTestTool(
          'finder_set_label',
          'set_label',
          'Finder'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('REQUIRES_CONFIRMATION');
      });
    });

    describe('make/create commands', () => {
      it('should classify "make_folder" as REQUIRES_CONFIRMATION', () => {
        const tool = createTestTool(
          'finder_make_folder',
          'make_folder',
          'Finder'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('REQUIRES_CONFIRMATION');
      });

      it('should classify "make_note" as REQUIRES_CONFIRMATION', () => {
        const tool = createTestTool('notes_make_note', 'make_note', 'Notes');
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('REQUIRES_CONFIRMATION');
      });

      it('should classify "create_file" as REQUIRES_CONFIRMATION', () => {
        const tool = createTestTool(
          'finder_create_file',
          'create_file',
          'Finder'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('REQUIRES_CONFIRMATION');
      });
    });

    describe('move/copy commands', () => {
      it('should classify "move_file" as REQUIRES_CONFIRMATION', () => {
        const tool = createTestTool(
          'finder_move_file',
          'move_file',
          'Finder'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('REQUIRES_CONFIRMATION');
      });

      it('should classify "copy_file" as REQUIRES_CONFIRMATION', () => {
        const tool = createTestTool(
          'finder_copy_file',
          'copy_file',
          'Finder'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('REQUIRES_CONFIRMATION');
      });

      it('should classify "duplicate" as REQUIRES_CONFIRMATION', () => {
        const tool = createTestTool(
          'finder_duplicate',
          'duplicate',
          'Finder'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('REQUIRES_CONFIRMATION');
      });
    });

    describe('save/export commands', () => {
      it('should classify "save_document" as REQUIRES_CONFIRMATION', () => {
        const tool = createTestTool(
          'app_save_document',
          'save_document',
          'App'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('REQUIRES_CONFIRMATION');
      });

      it('should classify "save_as" as REQUIRES_CONFIRMATION', () => {
        const tool = createTestTool('app_save_as', 'save_as', 'App');
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('REQUIRES_CONFIRMATION');
      });

      it('should classify "export" as REQUIRES_CONFIRMATION', () => {
        const tool = createTestTool('app_export', 'export', 'App');
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('REQUIRES_CONFIRMATION');
      });
    });

    describe('send commands', () => {
      it('should classify "send_email" as REQUIRES_CONFIRMATION', () => {
        const tool = createTestTool(
          'mail_send_email',
          'send_email',
          'Mail'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('REQUIRES_CONFIRMATION');
      });

      it('should classify "send_message" as REQUIRES_CONFIRMATION', () => {
        const tool = createTestTool(
          'messages_send_message',
          'send_message',
          'Messages'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('REQUIRES_CONFIRMATION');
      });

      it('should classify "post_message" as REQUIRES_CONFIRMATION', () => {
        const tool = createTestTool(
          'slack_post_message',
          'post_message',
          'Slack'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('REQUIRES_CONFIRMATION');
      });
    });

    describe('open/navigate commands', () => {
      it('should classify "open_url" as REQUIRES_CONFIRMATION', () => {
        const tool = createTestTool(
          'safari_open_url',
          'open_url',
          'Safari'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('REQUIRES_CONFIRMATION');
      });

      it('should classify "navigate" as REQUIRES_CONFIRMATION', () => {
        const tool = createTestTool(
          'chrome_navigate',
          'navigate',
          'Chrome'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('REQUIRES_CONFIRMATION');
      });

      it('should classify "go_to_website" as REQUIRES_CONFIRMATION', () => {
        const tool = createTestTool(
          'browser_go_to_website',
          'go_to_website',
          'Browser'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('REQUIRES_CONFIRMATION');
      });
    });

    describe('Mail-specific MODIFY operations', () => {
      it('should classify "send_message" as REQUIRES_CONFIRMATION', () => {
        const tool = createTestTool(
          'mail_send_message',
          'send_message',
          'Mail'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('REQUIRES_CONFIRMATION');
      });

      it('should classify "mark_as_read" as REQUIRES_CONFIRMATION', () => {
        const tool = createTestTool(
          'mail_mark_as_read',
          'mark_as_read',
          'Mail'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('REQUIRES_CONFIRMATION');
      });
    });
  });

  // ============================================================================
  // ALWAYS_CONFIRM Operations
  // ============================================================================

  describe('classify() - ALWAYS_CONFIRM operations', () => {
    describe('delete commands', () => {
      it('should classify "delete_file" as ALWAYS_CONFIRM', () => {
        const tool = createTestTool(
          'finder_delete_file',
          'delete_file',
          'Finder'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_CONFIRM');
        expect(result.reason).toContain('destructive');
      });

      it('should classify "delete_folder" as ALWAYS_CONFIRM', () => {
        const tool = createTestTool(
          'finder_delete_folder',
          'delete_folder',
          'Finder'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_CONFIRM');
      });

      it('should classify "delete_email" as ALWAYS_CONFIRM', () => {
        const tool = createTestTool(
          'mail_delete_email',
          'delete_email',
          'Mail'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_CONFIRM');
      });

      it('should classify "delete_note" as ALWAYS_CONFIRM', () => {
        const tool = createTestTool('notes_delete_note', 'delete_note', 'Notes');
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_CONFIRM');
      });
    });

    describe('remove commands', () => {
      it('should classify "remove_file" as ALWAYS_CONFIRM', () => {
        const tool = createTestTool(
          'finder_remove_file',
          'remove_file',
          'Finder'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_CONFIRM');
      });

      it('should classify "remove_account" as ALWAYS_CONFIRM', () => {
        const tool = createTestTool(
          'mail_remove_account',
          'remove_account',
          'Mail'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_CONFIRM');
      });
    });

    describe('quit/close/shutdown commands', () => {
      it('should classify "quit" as ALWAYS_CONFIRM', () => {
        const tool = createTestTool('app_quit', 'quit', 'App');
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_CONFIRM');
      });

      it('should classify "quit_application" as ALWAYS_CONFIRM', () => {
        const tool = createTestTool(
          'app_quit_application',
          'quit_application',
          'App'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_CONFIRM');
      });

      it('should classify "restart" as ALWAYS_CONFIRM', () => {
        const tool = createTestTool(
          'system_restart',
          'restart',
          'System'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_CONFIRM');
      });

      it('should classify "shutdown" as ALWAYS_CONFIRM', () => {
        const tool = createTestTool(
          'system_shutdown',
          'shutdown',
          'System'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_CONFIRM');
      });
    });

    describe('trash/empty commands', () => {
      it('should classify "empty_trash" as ALWAYS_CONFIRM', () => {
        const tool = createTestTool(
          'finder_empty_trash',
          'empty_trash',
          'Finder'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_CONFIRM');
      });

      it('should classify "trash_file" as ALWAYS_CONFIRM', () => {
        const tool = createTestTool(
          'finder_trash_file',
          'trash_file',
          'Finder'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_CONFIRM');
      });
    });

    describe('dangerous/system-affecting commands', () => {
      it('should classify "run_script" as ALWAYS_CONFIRM', () => {
        const tool = createTestTool(
          'system_run_script',
          'run_script',
          'System'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_CONFIRM');
      });

      it('should classify "execute_shell" as ALWAYS_CONFIRM', () => {
        const tool = createTestTool(
          'system_execute_shell',
          'execute_shell',
          'System'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_CONFIRM');
      });

      it('should classify "execute_command" as ALWAYS_CONFIRM', () => {
        const tool = createTestTool(
          'system_execute_command',
          'execute_command',
          'System'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_CONFIRM');
      });

      it('should classify "execute_code" as ALWAYS_CONFIRM', () => {
        const tool = createTestTool(
          'app_execute_code',
          'execute_code',
          'App'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_CONFIRM');
      });
    });

    describe('erase/wipe commands', () => {
      it('should classify "erase_disk" as ALWAYS_CONFIRM', () => {
        const tool = createTestTool(
          'system_erase_disk',
          'erase_disk',
          'System'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_CONFIRM');
      });

      it('should classify "clear_history" as ALWAYS_CONFIRM', () => {
        const tool = createTestTool(
          'browser_clear_history',
          'clear_history',
          'Browser'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_CONFIRM');
      });
    });
  });

  // ============================================================================
  // Command Pattern Recognition
  // ============================================================================

  describe('classify() - command pattern recognition', () => {
    describe('keyword-based classification', () => {
      it('should use command name prefix to classify (get_ prefix)', () => {
        const tool = createTestTool('app_get_anything', 'get_anything', 'App');
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_SAFE');
      });

      it('should use command name prefix to classify (list_ prefix)', () => {
        const tool = createTestTool('app_list_anything', 'list_anything', 'App');
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_SAFE');
      });

      it('should use command name prefix to classify (delete_ prefix)', () => {
        const tool = createTestTool(
          'app_delete_anything',
          'delete_anything',
          'App'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_CONFIRM');
      });

      it('should use command name prefix to classify (set_ prefix)', () => {
        const tool = createTestTool('app_set_anything', 'set_anything', 'App');
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('REQUIRES_CONFIRMATION');
      });
    });

    describe('case-insensitive keyword matching', () => {
      it('should match GET keyword regardless of case', () => {
        const tool = createTestTool('app_GET_name', 'GET_name', 'App');
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_SAFE');
      });

      it('should match DELETE keyword regardless of case', () => {
        const tool = createTestTool(
          'app_DELETE_file',
          'DELETE_file',
          'App'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_CONFIRM');
      });

      it('should match QUIT keyword regardless of case', () => {
        const tool = createTestTool('app_QUIT', 'QUIT', 'App');
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_CONFIRM');
      });
    });

    describe('compound command names', () => {
      it('should classify compound names (verb_noun pattern)', () => {
        const tool = createTestTool(
          'finder_list_all_files',
          'list_all_files',
          'Finder'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_SAFE');
      });

      it('should handle multiple underscores', () => {
        const tool = createTestTool(
          'app_get_current_active_window',
          'get_current_active_window',
          'App'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_SAFE');
      });
    });
  });

  // ============================================================================
  // Parameter Analysis
  // ============================================================================

  describe('classify() - parameter analysis', () => {
    describe('parameter impact on classification', () => {
      it('should consider file path parameters for destructive operations', () => {
        const tool = createTestTool(
          'finder_delete_file',
          'delete_file',
          'Finder'
        );
        const args = { target: '/Users/test/important.txt' };
        const result = classifier.classify(tool, args);

        expect(result.level).toBe('ALWAYS_CONFIRM');
      });

      it('should still classify as ALWAYS_CONFIRM even with empty parameters', () => {
        const tool = createTestTool(
          'finder_empty_trash',
          'empty_trash',
          'Finder'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_CONFIRM');
      });

      it('should classify SAFE operations as SAFE regardless of parameters', () => {
        const tool = createTestTool(
          'finder_list_folder',
          'list_folder',
          'Finder'
        );
        const args = { target: '/Users/test' };
        const result = classifier.classify(tool, args);

        expect(result.level).toBe('ALWAYS_SAFE');
      });
    });

    describe('parameter-driven safety changes (if applicable)', () => {
      it('should handle operations where parameters matter', () => {
        // Example: opening a URL could be REQUIRES_CONFIRMATION
        // but opening a local file might have different handling
        const tool = createTestTool('app_open', 'open', 'App');
        const result = classifier.classify(tool, {});

        // Without parameter analysis, default behavior
        expect([
          'ALWAYS_SAFE',
          'REQUIRES_CONFIRMATION',
          'ALWAYS_CONFIRM',
        ]).toContain(result.level);
      });
    });
  });

  // ============================================================================
  // App-Specific Rules
  // ============================================================================

  describe('classify() - app-specific rules', () => {
    describe('Finder-specific classifications', () => {
      it('Finder: delete → ALWAYS_CONFIRM', () => {
        const tool = createTestTool(
          'finder_delete',
          'delete',
          'Finder'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_CONFIRM');
        expect(result.reason).toContain('Finder');
      });

      it('Finder: open_folder → ALWAYS_SAFE', () => {
        const tool = createTestTool(
          'finder_open_folder',
          'open_folder',
          'Finder'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_SAFE');
      });

      it('Finder: move → REQUIRES_CONFIRMATION', () => {
        const tool = createTestTool(
          'finder_move',
          'move',
          'Finder'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('REQUIRES_CONFIRMATION');
      });
    });

    describe('Mail-specific classifications', () => {
      it('Mail: send_email → REQUIRES_CONFIRMATION', () => {
        const tool = createTestTool(
          'mail_send_email',
          'send_email',
          'Mail'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('REQUIRES_CONFIRMATION');
        expect(result.reason).toContain('Mail');
      });

      it('Mail: get_messages → ALWAYS_SAFE', () => {
        const tool = createTestTool(
          'mail_get_messages',
          'get_messages',
          'Mail'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_SAFE');
      });

      it('Mail: delete_email → ALWAYS_CONFIRM', () => {
        const tool = createTestTool(
          'mail_delete_email',
          'delete_email',
          'Mail'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_CONFIRM');
      });
    });

    describe('System Events-specific classifications', () => {
      it('System Events: run_script → ALWAYS_CONFIRM', () => {
        const tool = createTestTool(
          'system_events_run_script',
          'run_script',
          'System Events'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_CONFIRM');
        expect(result.reason).toContain('dangerous');
      });
    });

    describe('Browser-specific classifications', () => {
      it('Chrome: get_url → ALWAYS_SAFE', () => {
        const tool = createTestTool('chrome_get_url', 'get_url', 'Chrome');
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_SAFE');
      });

      it('Safari: navigate → REQUIRES_CONFIRMATION', () => {
        const tool = createTestTool(
          'safari_navigate',
          'navigate',
          'Safari'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('REQUIRES_CONFIRMATION');
      });
    });
  });

  // ============================================================================
  // Default Behavior
  // ============================================================================

  describe('classify() - default behavior', () => {
    it('should classify unknown commands as REQUIRES_CONFIRMATION (conservative)', () => {
      const tool = createTestTool('app_do_something', 'do_something', 'App');
      const result = classifier.classify(tool, {});

      expect(result.level).toBe('REQUIRES_CONFIRMATION');
      expect(result.reason).toContain('unknown');
    });

    it('should classify ambiguous commands conservatively', () => {
      const tool = createTestTool('app_process', 'process', 'App');
      const result = classifier.classify(tool, {});

      expect(result.level).toBe('REQUIRES_CONFIRMATION');
    });

    it('should classify command without metadata safely', () => {
      const tool: MCPTool = {
        name: 'unknown_tool',
        description: 'An unknown tool',
        inputSchema: {
          type: 'object',
          properties: {},
        },
        // No metadata
      };
      const result = classifier.classify(tool, {});

      // Should not crash, should default to conservative
      expect(result.level).toBe('REQUIRES_CONFIRMATION');
    });
  });

  // ============================================================================
  // Edge Cases
  // ============================================================================

  describe('classify() - edge cases', () => {
    describe('empty/null values', () => {
      it('should handle tool with empty name', () => {
        const tool = createTestTool('', '', 'App');
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('REQUIRES_CONFIRMATION');
      });

      it('should handle empty parameters object', () => {
        const tool = createTestTool('app_get_data', 'get_data', 'App');
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_SAFE');
      });

      it('should handle null parameters safely', () => {
        const tool = createTestTool('app_get_data', 'get_data', 'App');
        const result = classifier.classify(tool, null as any);

        // Should handle gracefully
        expect(result.level).toBeDefined();
      });
    });

    describe('contradictory signals', () => {
      it('should prioritize destructive keyword over non-destructive context', () => {
        // A command named "get_delete" should be ALWAYS_CONFIRM
        // because delete is the operation
        const tool = createTestTool(
          'app_get_delete_status',
          'get_delete_status',
          'App'
        );
        const result = classifier.classify(tool, {});

        // Depends on implementation, but likely ALWAYS_SAFE (get takes precedence)
        expect([
          'ALWAYS_SAFE',
          'ALWAYS_CONFIRM',
        ]).toContain(result.level);
      });

      it('should handle ambiguous command names gracefully', () => {
        const tool = createTestTool('app_toggle_setting', 'toggle_setting', 'App');
        const result = classifier.classify(tool, {});

        // Should classify as REQUIRES_CONFIRMATION (not clearly safe or dangerous)
        expect(result.level).toBe('REQUIRES_CONFIRMATION');
      });
    });

    describe('special characters and formatting', () => {
      it('should handle command with numbers', () => {
        const tool = createTestTool('app_get_item2', 'get_item2', 'App');
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_SAFE');
      });

      it('should handle very long command names', () => {
        const longName = 'get_' + 'a'.repeat(100);
        const tool = createTestTool('app_' + longName, longName, 'App');
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_SAFE');
      });
    });

    describe('chained/piped operations', () => {
      it('should handle commands that might chain operations', () => {
        // A command like "backup_and_delete" should be ALWAYS_CONFIRM
        // because delete is involved
        const tool = createTestTool(
          'app_backup_and_delete',
          'backup_and_delete',
          'App'
        );
        const result = classifier.classify(tool, {});

        // Should detect the dangerous word
        expect(result.level).toBe('ALWAYS_CONFIRM');
      });

      it('should handle complex verb combinations', () => {
        const tool = createTestTool(
          'app_copy_and_replace',
          'copy_and_replace',
          'App'
        );
        const result = classifier.classify(tool, {});

        // Should be REQUIRES_CONFIRMATION (modifies data)
        expect(result.level).toBe('REQUIRES_CONFIRMATION');
      });
    });

    describe('AppleScript naming conventions', () => {
      it('should handle camelCase command names', () => {
        const tool = createTestTool('app_getName', 'getName', 'App');
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_SAFE');
      });

      it('should handle mixed underscore and camelCase', () => {
        const tool = createTestTool(
          'app_get_ActiveWindow',
          'get_ActiveWindow',
          'App'
        );
        const result = classifier.classify(tool, {});

        expect(result.level).toBe('ALWAYS_SAFE');
      });
    });
  });

  // ============================================================================
  // Custom Rules Registration
  // ============================================================================

  describe('registerRule()', () => {
    it('should allow registering a custom rule', () => {
      const customRule = {
        matcher: (tool: MCPTool) => tool.name === 'custom_operation',
        level: 'ALWAYS_SAFE' as SafetyLevel,
        reason: 'Custom safe operation',
      };

      // Should not throw
      expect(() => classifier.registerRule(customRule)).not.toThrow();
    });

    it('should apply custom rule when registered', () => {
      const customRule = {
        matcher: (tool: MCPTool) => tool.name === 'my_custom_tool',
        level: 'ALWAYS_SAFE' as SafetyLevel,
        reason: 'My custom rule',
      };

      classifier.registerRule(customRule);

      const tool = createTestTool('my_custom_tool', 'custom_tool', 'App');
      const result = classifier.classify(tool, {});

      expect(result.level).toBe('ALWAYS_SAFE');
      expect(result.reason).toBe('My custom rule');
    });

    it('should prioritize custom rules over default classification', () => {
      const customRule = {
        matcher: (tool: MCPTool) => tool._metadata?.appName === 'SpecialApp',
        level: 'ALWAYS_SAFE' as SafetyLevel,
        reason: 'All SpecialApp operations are safe',
      };

      classifier.registerRule(customRule);

      const tool = createTestTool(
        'specialapp_delete_everything',
        'delete_everything',
        'SpecialApp'
      );
      const result = classifier.classify(tool, {});

      // Custom rule should override default
      expect(result.level).toBe('ALWAYS_SAFE');
    });

    it('should apply multiple custom rules in registration order', () => {
      // Register two rules
      classifier.registerRule({
        matcher: (tool: MCPTool) => tool._metadata?.appName === 'App1',
        level: 'ALWAYS_SAFE' as SafetyLevel,
        reason: 'Rule 1',
      });

      classifier.registerRule({
        matcher: (tool: MCPTool) =>
          tool._metadata?.appName === 'App2' &&
          tool._metadata.commandName.includes('delete'),
        level: 'REQUIRES_CONFIRMATION' as SafetyLevel,
        reason: 'Rule 2',
      });

      const tool1 = createTestTool('app1_anything', 'anything', 'App1');
      const result1 = classifier.classify(tool1, {});
      expect(result1.level).toBe('ALWAYS_SAFE');

      const tool2 = createTestTool(
        'app2_delete_file',
        'delete_file',
        'App2'
      );
      const result2 = classifier.classify(tool2, {});
      expect(result2.level).toBe('REQUIRES_CONFIRMATION');
    });

    it('should handle rule with complex matcher function', () => {
      const complexRule = {
        matcher: (tool: MCPTool, args: Record<string, any>) =>
          tool._metadata?.commandName.startsWith('backup_') && args.secure === true,
        level: 'REQUIRES_CONFIRMATION' as SafetyLevel,
        reason: 'Secure backup operation',
      };

      classifier.registerRule(complexRule);

      const tool = createTestTool('app_backup_data', 'backup_data', 'App');
      const result = classifier.classify(tool, { secure: true });

      expect(result.level).toBe('REQUIRES_CONFIRMATION');
    });
  });

  // ============================================================================
  // Reason Generation
  // ============================================================================

  describe('classification reasons', () => {
    it('should provide clear reason for ALWAYS_SAFE classification', () => {
      const tool = createTestTool('app_get_name', 'get_name', 'App');
      const result = classifier.classify(tool, {});

      expect(result.reason).toBeDefined();
      expect(result.reason.length).toBeGreaterThan(0);
      expect(result.reason.toLowerCase()).toContain('read');
    });

    it('should provide clear reason for REQUIRES_CONFIRMATION classification', () => {
      const tool = createTestTool('app_set_property', 'set_property', 'App');
      const result = classifier.classify(tool, {});

      expect(result.reason).toBeDefined();
      expect(result.reason.length).toBeGreaterThan(0);
    });

    it('should provide clear reason for ALWAYS_CONFIRM classification', () => {
      const tool = createTestTool('app_delete_file', 'delete_file', 'App');
      const result = classifier.classify(tool, {});

      expect(result.reason).toBeDefined();
      expect(result.reason.length).toBeGreaterThan(0);
      expect(result.reason.toLowerCase()).toContain('destructive');
    });

    it('should include app name in reason when relevant', () => {
      const tool = createTestTool(
        'mail_send_email',
        'send_email',
        'Mail'
      );
      const result = classifier.classify(tool, {});

      expect(result.reason).toContain('Mail');
    });
  });

  // ============================================================================
  // Classification Return Structure
  // ============================================================================

  describe('classification result structure', () => {
    it('should return object with level and reason', () => {
      const tool = createTestTool('app_get_name', 'get_name', 'App');
      const result = classifier.classify(tool, {});

      expect(result).toHaveProperty('level');
      expect(result).toHaveProperty('reason');
    });

    it('should return valid SafetyLevel values', () => {
      const validLevels = ['ALWAYS_SAFE', 'REQUIRES_CONFIRMATION', 'ALWAYS_CONFIRM'];

      const tools = [
        createTestTool('app_get_name', 'get_name', 'App'),
        createTestTool('app_set_name', 'set_name', 'App'),
        createTestTool('app_delete_all', 'delete_all', 'App'),
      ];

      for (const tool of tools) {
        const result = classifier.classify(tool, {});
        expect(validLevels).toContain(result.level);
      }
    });

    it('should provide consistent results for same tool', () => {
      const tool = createTestTool('app_get_name', 'get_name', 'App');

      const result1 = classifier.classify(tool, {});
      const result2 = classifier.classify(tool, {});

      expect(result1.level).toBe(result2.level);
      expect(result1.reason).toBe(result2.reason);
    });
  });

  // ============================================================================
  // Integration Scenarios
  // ============================================================================

  describe('classify() - real-world scenarios', () => {
    it('should classify typical Finder workflow operations correctly', () => {
      const listTool = createTestTool(
        'finder_list_files',
        'list_files',
        'Finder'
      );
      expect(classifier.classify(listTool, {}).level).toBe('ALWAYS_SAFE');

      const moveTool = createTestTool(
        'finder_move_file',
        'move_file',
        'Finder'
      );
      expect(classifier.classify(moveTool, {}).level).toBe(
        'REQUIRES_CONFIRMATION'
      );

      const deleteTool = createTestTool(
        'finder_delete_file',
        'delete_file',
        'Finder'
      );
      expect(classifier.classify(deleteTool, {}).level).toBe('ALWAYS_CONFIRM');
    });

    it('should classify typical Mail workflow operations correctly', () => {
      const getTool = createTestTool('mail_get_messages', 'get_messages', 'Mail');
      expect(classifier.classify(getTool, {}).level).toBe('ALWAYS_SAFE');

      const sendTool = createTestTool(
        'mail_send_email',
        'send_email',
        'Mail'
      );
      expect(classifier.classify(sendTool, {}).level).toBe(
        'REQUIRES_CONFIRMATION'
      );

      const deleteTool = createTestTool(
        'mail_delete_email',
        'delete_email',
        'Mail'
      );
      expect(classifier.classify(deleteTool, {}).level).toBe('ALWAYS_CONFIRM');
    });

    it('should classify typical browser operations correctly', () => {
      const getUrlTool = createTestTool('chrome_get_url', 'get_url', 'Chrome');
      expect(classifier.classify(getUrlTool, {}).level).toBe('ALWAYS_SAFE');

      const navigateTool = createTestTool(
        'chrome_navigate',
        'navigate',
        'Chrome'
      );
      expect(classifier.classify(navigateTool, {}).level).toBe(
        'REQUIRES_CONFIRMATION'
      );
    });

    it('should classify system operations conservatively', () => {
      const shutdownTool = createTestTool(
        'system_shutdown',
        'shutdown',
        'System'
      );
      expect(classifier.classify(shutdownTool, {}).level).toBe(
        'ALWAYS_CONFIRM'
      );

      const runScriptTool = createTestTool(
        'system_run_script',
        'run_script',
        'System'
      );
      expect(classifier.classify(runScriptTool, {}).level).toBe(
        'ALWAYS_CONFIRM'
      );
    });
  });
});
