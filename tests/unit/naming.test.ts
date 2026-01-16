import { describe, it, expect, beforeEach } from 'vitest';
import { NamingUtility } from '../../src/jitd/tool-generator/naming.js';
import type { SDEFCommand } from '../../src/types/sdef.js';

describe('NamingUtility', () => {
  let naming: NamingUtility;

  beforeEach(() => {
    naming = new NamingUtility();
  });

  describe('generateToolName', () => {
    it('should generate standard tool name from simple command and app', () => {
      const command: SDEFCommand = {
        name: 'open',
        code: 'aevtodoc',
        description: 'Open a file',
        parameters: [],
      };

      const toolName = naming.generateToolName(command, 'Finder');
      expect(toolName).toBe('finder_open');
    });

    it('should generate tool name with multi-word command', () => {
      const command: SDEFCommand = {
        name: 'test command',
        code: 'testcmnd',
        description: 'Test command',
        parameters: [],
      };

      const toolName = naming.generateToolName(command, 'TestApp');
      expect(toolName).toBe('testapp_test_command');
    });

    it('should normalize command names with spaces to underscores', () => {
      const command: SDEFCommand = {
        name: 'copy items',
        code: 'copyitem',
        description: 'Copy items',
        parameters: [],
      };

      const toolName = naming.generateToolName(command, 'Finder');
      expect(toolName).toBe('finder_copy_items');
    });

    it('should remove special characters from command names', () => {
      const command: SDEFCommand = {
        name: 'copy/paste',
        code: 'copypste',
        description: 'Copy and paste',
        parameters: [],
      };

      const toolName = naming.generateToolName(command, 'TestApp');
      expect(toolName).toBe('testapp_copy_paste');
    });

    it('should collapse multiple consecutive spaces or underscores', () => {
      const command: SDEFCommand = {
        name: 'test   command___name',
        code: 'testcmnd',
        description: 'Test command',
        parameters: [],
      };

      const toolName = naming.generateToolName(command, 'TestApp');
      expect(toolName).toBe('testapp_test_command_name');
    });

    it('should convert all characters to lowercase', () => {
      const command: SDEFCommand = {
        name: 'OpenFile',
        code: 'openfile',
        description: 'Open file',
        parameters: [],
      };

      const toolName = naming.generateToolName(command, 'Safari');
      expect(toolName).toBe('safari_openfile');
    });

    it('should handle app names with spaces and mixed case', () => {
      const command: SDEFCommand = {
        name: 'navigate',
        code: 'navgturl',
        description: 'Navigate to URL',
        parameters: [],
      };

      const toolName = naming.generateToolName(command, 'Google Chrome');
      expect(toolName).toBe('google_chrome_navigate');
    });

    it('should truncate tool names exceeding 64 characters', () => {
      const command: SDEFCommand = {
        name: 'this is a very long command name that exceeds the maximum allowed length for tool names',
        code: 'longcmnd',
        description: 'Very long command',
        parameters: [],
      };

      const toolName = naming.generateToolName(command, 'TestApp');
      expect(toolName.length).toBeLessThanOrEqual(64);
      expect(toolName).toMatch(/^testapp_this_is_a_very_long_command_name/);
    });

    it('should add hash suffix when truncating to ensure uniqueness', () => {
      const command1: SDEFCommand = {
        name: 'this is a very long command name that exceeds maximum length alpha',
        code: 'longcmd1',
        description: 'Long command 1',
        parameters: [],
      };

      const command2: SDEFCommand = {
        name: 'this is a very long command name that exceeds maximum length beta',
        code: 'longcmd2',
        description: 'Long command 2',
        parameters: [],
      };

      const toolName1 = naming.generateToolName(command1, 'TestApp');
      const toolName2 = naming.generateToolName(command2, 'TestApp');

      expect(toolName1).not.toBe(toolName2);
      expect(toolName1.length).toBeLessThanOrEqual(64);
      expect(toolName2.length).toBeLessThanOrEqual(64);
    });

    it('should handle empty command name gracefully', () => {
      const command: SDEFCommand = {
        name: '',
        code: 'emptycmd',
        description: 'Empty command',
        parameters: [],
      };

      const toolName = naming.generateToolName(command, 'TestApp');
      expect(toolName).toBeTruthy();
      expect(toolName).toMatch(/^testapp_/);
    });

    it('should handle command name with only special characters', () => {
      const command: SDEFCommand = {
        name: '!!!@@@###',
        code: 'spclchar',
        description: 'Special chars',
        parameters: [],
      };

      const toolName = naming.generateToolName(command, 'TestApp');
      expect(toolName).toBeTruthy();
      expect(toolName).toMatch(/^testapp_/);
    });

    it('should handle Unicode and non-ASCII characters', () => {
      const command: SDEFCommand = {
        name: 'öffnen文件',
        code: 'openfil',
        description: 'Open file',
        parameters: [],
      };

      const toolName = naming.generateToolName(command, 'TestApp');
      expect(toolName).toMatch(/^testapp_/);
      // Should only contain ASCII alphanumeric and underscores
      expect(toolName).toMatch(/^[a-z0-9_]+$/);
    });

    it('should append suite name to resolve collisions when provided', () => {
      const command: SDEFCommand = {
        name: 'open',
        code: 'openfile',
        description: 'Open file',
        parameters: [],
      };

      const toolName = naming.generateToolName(command, 'Finder', 'custom suite');
      expect(toolName).toBe('finder_custom_suite_open');
    });
  });

  describe('sanitizeParameterName', () => {
    it('should convert spaces to underscores', () => {
      expect(naming.sanitizeParameterName('with properties')).toBe('with_properties');
    });

    it('should preserve alphanumeric characters and underscores', () => {
      expect(naming.sanitizeParameterName('file_path123')).toBe('file_path123');
    });

    it('should remove special characters', () => {
      expect(naming.sanitizeParameterName('file-name!@#')).toBe('file_name');
    });

    it('should convert to lowercase', () => {
      expect(naming.sanitizeParameterName('FileName')).toBe('filename');
    });

    it('should collapse multiple consecutive underscores', () => {
      expect(naming.sanitizeParameterName('file___name')).toBe('file_name');
    });

    it('should handle parameter name with only special characters', () => {
      const result = naming.sanitizeParameterName('!!!@@@');
      expect(result).toBeTruthy();
      expect(result).toMatch(/^[a-z0-9_]+$/);
    });

    it('should handle empty parameter name', () => {
      const result = naming.sanitizeParameterName('');
      expect(result).toBeTruthy();
    });

    it('should handle Unicode characters in parameter names', () => {
      const result = naming.sanitizeParameterName('archivéфайл');
      expect(result).toMatch(/^[a-z0-9_]+$/);
    });
  });

  describe('checkNameCollision', () => {
    it('should return true when name exists in existing tools', () => {
      const existingTools = [
        { name: 'finder_open' },
        { name: 'finder_close' },
        { name: 'safari_navigate' },
      ];

      expect(naming.checkNameCollision('finder_open', existingTools)).toBe(true);
    });

    it('should return false when name does not exist in existing tools', () => {
      const existingTools = [
        { name: 'finder_open' },
        { name: 'finder_close' },
      ];

      expect(naming.checkNameCollision('finder_delete', existingTools)).toBe(false);
    });

    it('should return false for empty existing tools array', () => {
      expect(naming.checkNameCollision('finder_open', [])).toBe(false);
    });

    it('should be case-sensitive in collision detection', () => {
      const existingTools = [{ name: 'finder_open' }];

      expect(naming.checkNameCollision('Finder_Open', existingTools)).toBe(false);
    });
  });

  describe('resolveCollision', () => {
    it('should append suite name to resolve collision', () => {
      const existingTools = [{ name: 'finder_open' }];

      const resolved = naming.resolveCollision('finder_open', existingTools, 'standard suite');
      expect(resolved).toBe('finder_standard_suite_open');
    });

    it('should handle multiple collisions by appending incrementing suffix', () => {
      const existingTools = [
        { name: 'finder_open' },
        { name: 'finder_standard_suite_open' },
      ];

      const resolved = naming.resolveCollision('finder_open', existingTools, 'standard suite');
      expect(resolved).not.toBe('finder_open');
      expect(resolved).not.toBe('finder_standard_suite_open');
    });

    it('should resolve collision without suite name by appending numeric suffix', () => {
      const existingTools = [{ name: 'finder_open' }];

      const resolved = naming.resolveCollision('finder_open', existingTools);
      expect(resolved).toMatch(/^finder_open_\d+$/);
    });

    it('should return original name if no collision exists', () => {
      const existingTools = [{ name: 'finder_close' }];

      const resolved = naming.resolveCollision('finder_open', existingTools, 'standard suite');
      expect(resolved).toBe('finder_open');
    });

    it('should handle collision resolution with suite name normalization', () => {
      const existingTools = [{ name: 'finder_open' }];

      const resolved = naming.resolveCollision('finder_open', existingTools, 'Custom Suite Name');
      expect(resolved).toBe('finder_custom_suite_name_open');
    });
  });

  describe('normalize', () => {
    // This is a private method, but we can test it indirectly through public methods
    it('should normalize through generateToolName - mixed case and spaces', () => {
      const command: SDEFCommand = {
        name: 'Test Command Name',
        code: 'testcmnd',
        description: 'Test',
        parameters: [],
      };

      const toolName = naming.generateToolName(command, 'Test App');
      expect(toolName).toBe('test_app_test_command_name');
    });

    it('should normalize through sanitizeParameterName - remove invalid chars', () => {
      expect(naming.sanitizeParameterName('test@param#name')).toBe('test_param_name');
    });
  });

  describe('constructor with options', () => {
    it('should support app_prefix strategy by default', () => {
      const naming = new NamingUtility();
      const command: SDEFCommand = {
        name: 'open',
        code: 'openfile',
        description: 'Open',
        parameters: [],
      };

      const toolName = naming.generateToolName(command, 'Finder');
      expect(toolName).toBe('finder_open');
    });

    it('should support suite_prefix strategy', () => {
      const naming = new NamingUtility({ strategy: 'suite_prefix' });
      const command: SDEFCommand = {
        name: 'open',
        code: 'openfile',
        description: 'Open',
        parameters: [],
      };

      const toolName = naming.generateToolName(command, 'Finder', 'standard suite');
      expect(toolName).toBe('standard_suite_open');
    });

    it('should support fully_qualified strategy', () => {
      const naming = new NamingUtility({ strategy: 'fully_qualified' });
      const command: SDEFCommand = {
        name: 'open',
        code: 'openfile',
        description: 'Open',
        parameters: [],
      };

      const toolName = naming.generateToolName(command, 'Finder', 'standard suite');
      expect(toolName).toBe('finder_standard_suite_open');
    });
  });
});
