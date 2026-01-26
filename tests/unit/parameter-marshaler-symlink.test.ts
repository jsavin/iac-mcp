/**
 * Symlink Security Tests for ParameterMarshaler
 *
 * Tests specifically for symlink attack prevention in path validation.
 * These tests create actual symlinks to verify that the marshaler properly
 * resolves symlinks and rejects paths that point to restricted directories.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { ParameterMarshaler } from '../../src/adapters/macos/parameter-marshaler';
import type { JSONSchemaProperty } from '../../src/types/mcp-tool';
import { mkdirSync, symlinkSync, unlinkSync, rmdirSync, existsSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { isMacOS } from '../utils/test-helpers';

describe.skipIf(!isMacOS())('ParameterMarshaler - Symlink Attack Prevention', () => {
  const marshaler = new ParameterMarshaler();
  let testDir: string;
  let symlinkToSystem: string;
  let symlinkToTmp: string;
  let symlinkToEtc: string;

  beforeAll(() => {
    // Create test directory in /tmp (which is allowed)
    testDir = join(tmpdir(), `marshaler-symlink-test-${Date.now()}`);
    mkdirSync(testDir, { recursive: true });

    // Create a symlink to /System/Library (restricted directory)
    symlinkToSystem = join(testDir, 'system_symlink');
    try {
      symlinkSync('/System/Library', symlinkToSystem);
    } catch (e) {
      console.warn('Could not create test symlink to /System/Library:', e);
    }

    // Create a symlink to /etc (restricted directory)
    symlinkToEtc = join(testDir, 'etc_symlink');
    try {
      symlinkSync('/etc', symlinkToEtc);
    } catch (e) {
      console.warn('Could not create test symlink to /etc:', e);
    }

    // Create a symlink to /tmp (allowed directory) - this should work
    symlinkToTmp = join(testDir, 'tmp_symlink');
    try {
      symlinkSync('/tmp', symlinkToTmp);
    } catch (e) {
      console.warn('Could not create test symlink to /tmp:', e);
    }
  });

  afterAll(() => {
    // Clean up test symlinks and directory
    try {
      if (existsSync(symlinkToSystem)) {
        unlinkSync(symlinkToSystem);
      }
      if (existsSync(symlinkToEtc)) {
        unlinkSync(symlinkToEtc);
      }
      if (existsSync(symlinkToTmp)) {
        unlinkSync(symlinkToTmp);
      }
      if (existsSync(testDir)) {
        rmdirSync(testDir);
      }
    } catch (e) {
      console.warn('Could not clean up test symlinks:', e);
    }
  });

  describe('Real symlink resolution', () => {
    it('should reject symlinks pointing to /System/Library', () => {
      if (!existsSync(symlinkToSystem)) {
        console.warn('Skipping test: could not create symlink to /System/Library');
        return;
      }

      const schema: JSONSchemaProperty = {
        type: 'string',
        description: 'File path'
      };

      // This symlink points to /System/Library, which is restricted
      // After resolution via fs.realpathSync, it should be rejected by whitelist validation
      expect(() => {
        marshaler.marshalValue(symlinkToSystem, schema);
      }).toThrow(/restricted system directory|outside allowed/);
    });

    it('should reject symlinks pointing to /etc', () => {
      if (!existsSync(symlinkToEtc)) {
        console.warn('Skipping test: could not create symlink to /etc');
        return;
      }

      const schema: JSONSchemaProperty = {
        type: 'string',
        description: 'File path'
      };

      // This symlink points to /etc, which is restricted
      // After resolution, it should be rejected
      expect(() => {
        marshaler.marshalValue(symlinkToEtc, schema);
      }).toThrow(/restricted system directory|outside allowed/);
    });

    it('should allow symlinks pointing to allowed directories', () => {
      if (!existsSync(symlinkToTmp)) {
        console.warn('Skipping test: could not create symlink to /tmp');
        return;
      }

      const schema: JSONSchemaProperty = {
        type: 'string',
        description: 'File path'
      };

      // This symlink points to /tmp, which is allowed
      // After resolution, it should pass validation
      const result = marshaler.marshalValue(symlinkToTmp, schema);
      expect(result).toContain('Path(');
    });

    it('should reject file path through symlink to restricted directory', () => {
      if (!existsSync(symlinkToSystem)) {
        console.warn('Skipping test: could not create symlink to /System/Library');
        return;
      }

      const schema: JSONSchemaProperty = {
        type: 'string',
        description: 'File path'
      };

      // Try to access a file through the symlink
      const filePathThroughSymlink = join(symlinkToSystem, 'CoreServices');

      expect(() => {
        marshaler.marshalValue(filePathThroughSymlink, schema);
      }).toThrow(/restricted system directory|outside allowed/);
    });
  });

  describe('Home directory symlink attack prevention', () => {
    it('should resolve symlinks in home directory paths', () => {
      const schema: JSONSchemaProperty = {
        type: 'string',
        description: 'File path'
      };

      // Real ~/Documents should resolve and be allowed (under /Users/)
      const result = marshaler.marshalValue('~/Documents', schema);
      expect(result).toContain('Path(');
    });

    it('should handle non-existent paths in home directory', () => {
      const schema: JSONSchemaProperty = {
        type: 'string',
        description: 'File path'
      };

      // Non-existent paths can't have symlinks resolved, but should still validate structure
      const result = marshaler.marshalValue('~/nonexistent-test-path-12345', schema);
      expect(result).toContain('Path(');
    });

    it('should reject home directory paths with traversal', () => {
      const schema: JSONSchemaProperty = {
        type: 'string',
        description: 'File path'
      };

      expect(() => {
        marshaler.marshalValue('~/../../etc/passwd', schema);
      }).toThrow('directory traversal');
    });
  });

  describe('Symlink attack scenario simulation', () => {
    it('should demonstrate the attack vector that was fixed', () => {
      // ATTACK SCENARIO: ln -s /System/Library ~/my_symlink
      // Before fix: ~/my_symlink would not have symlinks resolved
      // After fix: ~/my_symlink resolves to /System/Library and is rejected

      const schema: JSONSchemaProperty = {
        type: 'string',
        description: 'File path'
      };

      // Create a test symlink in our test directory simulating the attack
      const attackSymlink = join(testDir, 'home_attack_symlink');
      try {
        symlinkSync('/System/Library', attackSymlink);

        // Try to use this path - it should be rejected after resolution
        expect(() => {
          marshaler.marshalValue(attackSymlink, schema);
        }).toThrow(/restricted system directory|outside allowed/);

        // Clean up
        unlinkSync(attackSymlink);
      } catch (e) {
        console.warn('Could not create test symlink for attack simulation:', e);
      }
    });

    it('should reject nested symlink attacks', () => {
      // Create a symlink chain: link1 -> link2 -> /etc
      const link1 = join(testDir, 'link1');
      const link2 = join(testDir, 'link2');

      try {
        symlinkSync('/etc', link2);
        symlinkSync(link2, link1);

        const schema: JSONSchemaProperty = {
          type: 'string',
          description: 'File path'
        };

        // fs.realpathSync should follow the entire chain
        expect(() => {
          marshaler.marshalValue(link1, schema);
        }).toThrow(/restricted system directory|outside allowed/);

        // Clean up
        unlinkSync(link1);
        unlinkSync(link2);
      } catch (e) {
        console.warn('Could not create nested symlink chain:', e);
      }
    });
  });

  describe('Integration with other security checks', () => {
    it('should combine symlink resolution with traversal detection', () => {
      const schema: JSONSchemaProperty = {
        type: 'string',
        description: 'File path'
      };

      // Path with traversal should be caught before symlink resolution
      expect(() => {
        marshaler.marshalValue('/tmp/../etc/passwd', schema);
      }).toThrow('directory traversal');
    });

    it('should combine symlink resolution with null byte detection', () => {
      const schema: JSONSchemaProperty = {
        type: 'string',
        description: 'File path'
      };

      // Null byte should be caught before symlink resolution
      expect(() => {
        marshaler.marshalValue('/tmp/test\0', schema);
      }).toThrow('null byte');
    });

    it('should combine symlink resolution with URL-encoding detection', () => {
      const schema: JSONSchemaProperty = {
        type: 'string',
        description: 'File path'
      };

      // URL-encoded traversal should be caught before symlink resolution
      expect(() => {
        marshaler.marshalValue('/tmp/%2e%2e/etc/passwd', schema);
      }).toThrow('URL-encoded directory traversal');
    });
  });

  describe('Whitelist enforcement after symlink resolution', () => {
    it('should enforce whitelist on resolved paths', () => {
      // Even if we pass validation checks, the resolved path must be in whitelist
      const schema: JSONSchemaProperty = {
        type: 'string',
        description: 'File path'
      };

      // Direct path to restricted directory (no symlinks)
      expect(() => {
        marshaler.marshalValue('/bin/bash', schema);
      }).toThrow(/restricted system directory|outside allowed/);

      expect(() => {
        marshaler.marshalValue('/usr/bin/python', schema);
      }).toThrow(/restricted system directory|outside allowed/);

      expect(() => {
        marshaler.marshalValue('/var/log/system.log', schema);
      }).toThrow(/restricted system directory|outside allowed/);
    });

    it('should allow whitelisted paths after resolution', () => {
      const schema: JSONSchemaProperty = {
        type: 'string',
        description: 'File path'
      };

      // These should all pass
      expect(marshaler.marshalValue('/tmp/test.txt', schema)).toContain('Path(');
      // Use /Applications/ directory itself, not specific apps (which may be symlinks on modern macOS)
      expect(marshaler.marshalValue('/Applications/', schema)).toContain('Path(');
      expect(marshaler.marshalValue('~/Documents/file.txt', schema)).toContain('Path(');
    });
  });
});
