/**
 * Error Message Path Sanitization Tests
 *
 * Tests the new error-sanitization utility module that preserves system paths
 * while sanitizing user paths (Low-1 improvement from bot review)
 */

import { describe, it, expect } from 'vitest';
import { sanitizeErrorMessage, sanitizeError } from '../../src/utils/error-sanitization.js';

describe('Error Sanitization Utility', () => {
  describe('System Path Preservation', () => {
    it('should preserve /Applications paths', () => {
      const message = 'Failed to parse SDEF at /Applications/Safari.app/Contents/Resources/Safari.sdef';
      const sanitized = sanitizeErrorMessage(message);

      expect(sanitized).toContain('/Applications/Safari.app');
      expect(sanitized).toContain('Safari.sdef');
    });

    it('should preserve /System/Library paths', () => {
      const message = 'Error reading /System/Library/CoreServices/Finder.app/Contents/Resources/Finder.sdef';
      const sanitized = sanitizeErrorMessage(message);

      expect(sanitized).toContain('/System/Library/CoreServices/Finder.app');
      expect(sanitized).toContain('Finder.sdef');
    });

    it('should preserve /System paths generally', () => {
      const message = 'Failed at /System/Applications/Mail.app/Contents/Resources/Mail.sdef';
      const sanitized = sanitizeErrorMessage(message);

      expect(sanitized).toContain('/System/Applications/Mail.app');
      expect(sanitized).toContain('Mail.sdef');
    });

    it('should preserve /Library paths', () => {
      const message = 'Error in /Library/ScriptingAdditions/SomeApp.osax/Contents/Resources/SomeApp.sdef';
      const sanitized = sanitizeErrorMessage(message);

      expect(sanitized).toContain('/Library/ScriptingAdditions/SomeApp.osax');
      expect(sanitized).toContain('SomeApp.sdef');
    });
  });

  describe('User Path Sanitization', () => {
    it('should sanitize /Users/username paths', () => {
      const message = 'Failed to parse SDEF at /Users/jake/Applications/MyApp.app/Contents/Resources/MyApp.sdef';
      const sanitized = sanitizeErrorMessage(message);

      expect(sanitized).not.toContain('/Users/jake');
      expect(sanitized).toContain('/Users/[user]');
      expect(sanitized).toContain('MyApp.app');
    });

    it('should sanitize /home/username paths (Linux)', () => {
      const message = 'Error in /home/jane/projects/app/config.json';
      const sanitized = sanitizeErrorMessage(message);

      expect(sanitized).not.toContain('/home/jane');
      expect(sanitized).toContain('/home/[user]');
    });

    it('should sanitize paths containing $HOME value', () => {
      const message = 'Failed to read /Users/testuser/Library/Preferences/com.test.plist';
      const sanitized = sanitizeErrorMessage(message);

      expect(sanitized).not.toContain('/Users/testuser');
      expect(sanitized).toContain('/Users/[user]');
    });

    it('should preserve tilde notation (does not expand)', () => {
      const message = 'Config not found at ~/Library/Application Support/MyApp/settings.json';
      const sanitized = sanitizeErrorMessage(message);

      // Tilde is not expanded by the utility (left as-is)
      expect(sanitized).toContain('~/');
      expect(sanitized).toContain('MyApp');
    });
  });

  describe('Mixed Paths', () => {
    it('should preserve system paths while sanitizing user paths in same message', () => {
      const message = 'Error: /Applications/Safari.app tried to access /Users/bob/Documents/file.txt';
      const sanitized = sanitizeErrorMessage(message);

      expect(sanitized).toContain('/Applications/Safari.app');
      expect(sanitized).not.toContain('/Users/bob');
      expect(sanitized).toContain('/Users/[user]');
    });

    it('should handle multiple user paths', () => {
      const message = 'Copying from /Users/alice/file.txt to /Users/bob/backup.txt';
      const sanitized = sanitizeErrorMessage(message);

      expect(sanitized).not.toContain('alice');
      expect(sanitized).not.toContain('bob');
      expect(sanitized).toContain('/Users/[user]');
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty strings', () => {
      expect(sanitizeErrorMessage('')).toBe('');
    });

    it('should handle messages with no paths', () => {
      const message = 'Connection timeout';
      expect(sanitizeErrorMessage(message)).toBe(message);
    });

    it('should not over-sanitize paths that look like users', () => {
      const message = '/Applications/UserAdmin.app/Contents/Resources/User.sdef';
      const sanitized = sanitizeErrorMessage(message);

      expect(sanitized).toContain('/Applications/UserAdmin.app');
      expect(sanitized).toContain('User.sdef');
    });

    it('should handle Windows-style paths', () => {
      const message = 'Error at C:\\Users\\admin\\Documents\\file.txt';
      const sanitized = sanitizeErrorMessage(message);

      // Should remain unchanged (macOS-focused utility)
      expect(sanitized).toBe(message);
    });
  });

  describe('sanitizeError function', () => {
    it('should sanitize Error objects', () => {
      const error = new Error('Failed at /Users/test/path/file.txt');
      const sanitized = sanitizeError(error);

      expect(sanitized.message).not.toContain('/Users/test');
      expect(sanitized.message).toContain('/Users/[user]');
    });

    it('should preserve error type', () => {
      class CustomError extends Error {
        constructor(message: string) {
          super(message);
          this.name = 'CustomError';
        }
      }

      const error = new CustomError('Error at /Users/admin/file.txt');
      const sanitized = sanitizeError(error);

      expect(sanitized.name).toBe('CustomError');
      expect(sanitized.message).toContain('/Users/[user]');
    });
  });

  describe('Real-World Examples', () => {
    it('should sanitize typical SDEF parsing errors', () => {
      const message = 'XMLParser error at line 42 in /Users/developer/Library/Application Support/MyApp/cache/Pages.sdef: Unexpected token';
      const sanitized = sanitizeErrorMessage(message);

      expect(sanitized).not.toContain('developer');
      expect(sanitized).toContain('/Users/[user]');
      expect(sanitized).toContain('Pages.sdef');
      expect(sanitized).toContain('line 42');
    });

    it('should sanitize file system errors', () => {
      const message = 'ENOENT: no such file or directory, open \'/Users/john/.config/app/settings.json\'';
      const sanitized = sanitizeErrorMessage(message);

      expect(sanitized).not.toContain('john');
      expect(sanitized).toContain('/Users/[user]');
      expect(sanitized).toContain('ENOENT');
    });

    it('should sanitize permission errors', () => {
      const message = 'EACCES: permission denied, access \'/Users/admin/secure/data.db\'';
      const sanitized = sanitizeErrorMessage(message);

      expect(sanitized).not.toContain('admin');
      expect(sanitized).toContain('/Users/[user]');
      expect(sanitized).toContain('EACCES');
    });

    it('should preserve helpful debug info while sanitizing paths', () => {
      const message = 'Failed to parse /Applications/Safari.app/Contents/Resources/Safari.sdef: Referenced include file not found at /Users/dev/Documents/includes/Standard.sdef';
      const sanitized = sanitizeErrorMessage(message);

      expect(sanitized).toContain('/Applications/Safari.app');
      expect(sanitized).not.toContain('/Users/dev');
      expect(sanitized).toContain('/Users/[user]');
      expect(sanitized).toContain('Standard.sdef');
    });
  });

  describe('Username with Spaces (Bot Review Fix)', () => {
    it('should sanitize usernames with spaces correctly', () => {
      const message = 'Error at /Users/john doe/Documents/file.txt';
      const sanitized = sanitizeErrorMessage(message);

      expect(sanitized).not.toContain('john doe');
      expect(sanitized).not.toContain('john');
      expect(sanitized).not.toContain('doe');
      expect(sanitized).toContain('/Users/[user]/Documents/file.txt');
    });

    it('should sanitize Linux usernames with spaces', () => {
      const message = 'Failed at /home/jane doe/projects/app.js';
      const sanitized = sanitizeErrorMessage(message);

      expect(sanitized).not.toContain('jane doe');
      expect(sanitized).not.toContain('jane');
      expect(sanitized).not.toContain('doe');
      expect(sanitized).toContain('/home/[user]/projects/app.js');
    });
  });
});
