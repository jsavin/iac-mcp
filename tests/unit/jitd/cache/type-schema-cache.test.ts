import { describe, it, expect, beforeEach, vi } from 'vitest';
import { TypeSchemaCacheManager } from '../../../../src/jitd/cache/type-schema-cache.js';
import * as fs from 'fs/promises';

// Mock dependencies
vi.mock('fs/promises');
vi.mock('../../../../src/jitd/discovery/class-parser.js');
vi.mock('../../../../src/jitd/type-generator/type-generator.js');

import { parseSDEFClasses } from '../../../../src/jitd/discovery/class-parser.js';
import { generateTypeScriptTypes } from '../../../../src/jitd/type-generator/type-generator.js';

describe('TypeSchemaCacheManager', () => {
  let cacheManager: TypeSchemaCacheManager;

  beforeEach(() => {
    cacheManager = new TypeSchemaCacheManager();
    vi.clearAllMocks();
  });

  describe('constructor', () => {
    it('should initialize with empty cache', () => {
      expect(cacheManager.size()).toBe(0);
    });
  });

  describe('getOrParse() - cache hit', () => {
    it('should return cached schema when valid and not stale', async () => {
      const bundleId = 'com.apple.finder';
      const sdefPath = '/path/to/Finder.sdef';
      const mockSDEFContent = '<?xml version="1.0"?><dictionary></dictionary>';
      const mockClasses = [
        {
          name: 'document',
          code: 'docu',
          properties: [],
          elements: [],
        },
      ];
      const mockEnumerations = [];
      const mockTypeScript = 'export type Document = { };';

      // Mock file operations
      vi.mocked(fs.readFile).mockResolvedValue(mockSDEFContent);
      vi.mocked(fs.stat).mockResolvedValue({
        mtime: new Date('2024-01-01'),
      } as any);

      vi.mocked(parseSDEFClasses).mockReturnValue({
        classes: mockClasses,
        enumerations: mockEnumerations,
        classExtensions: [],
      });

      vi.mocked(generateTypeScriptTypes).mockReturnValue(mockTypeScript);

      // First call - should parse and cache
      const result1 = await cacheManager.getOrParse(bundleId, sdefPath);
      expect(result1.classes).toEqual(mockClasses);
      expect(result1.typescriptCode).toBe(mockTypeScript);

      // Update mtime to be older (cache should not be stale)
      vi.mocked(fs.stat).mockResolvedValue({
        mtime: new Date('2023-01-01'),
      } as any);

      // Second call - should return cached result without re-parsing
      const result2 = await cacheManager.getOrParse(bundleId, sdefPath);
      expect(result2.classes).toEqual(mockClasses);
      expect(result2.typescriptCode).toBe(mockTypeScript);

      // parseSDEFClasses should have been called only once
      expect(vi.mocked(parseSDEFClasses)).toHaveBeenCalledTimes(1);
    });

    it('should return same TypeScript code from cache', async () => {
      const bundleId = 'com.apple.safari';
      const sdefPath = '/path/to/Safari.sdef';
      const mockTypeScript = 'export type Tab = { name: string };';

      vi.mocked(fs.readFile).mockResolvedValue('<?xml version="1.0"?><dictionary></dictionary>');
      vi.mocked(fs.stat).mockResolvedValue({
        mtime: new Date('2024-01-01'),
      } as any);

      vi.mocked(parseSDEFClasses).mockReturnValue({
        classes: [],
        enumerations: [],
        classExtensions: [],
      });

      vi.mocked(generateTypeScriptTypes).mockReturnValue(mockTypeScript);

      const result1 = await cacheManager.getOrParse(bundleId, sdefPath);
      const result2 = await cacheManager.getOrParse(bundleId, sdefPath);

      expect(result1.typescriptCode).toBe(result2.typescriptCode);
      expect(result1.typescriptCode).toBe(mockTypeScript);
    });

    it('should cache result after first parse', async () => {
      const bundleId = 'com.apple.mail';
      const sdefPath = '/path/to/Mail.sdef';

      vi.mocked(fs.readFile).mockResolvedValue('<?xml version="1.0"?><dictionary></dictionary>');
      vi.mocked(fs.stat).mockResolvedValue({
        mtime: new Date('2024-01-01'),
      } as any);

      vi.mocked(parseSDEFClasses).mockReturnValue({
        classes: [],
        enumerations: [],
        classExtensions: [],
      });

      vi.mocked(generateTypeScriptTypes).mockReturnValue('');

      expect(cacheManager.size()).toBe(0);

      await cacheManager.getOrParse(bundleId, sdefPath);
      expect(cacheManager.size()).toBe(1);

      await cacheManager.getOrParse(bundleId, sdefPath);
      expect(cacheManager.size()).toBe(1); // Still 1, not duplicated
    });
  });

  describe('getOrParse() - cache miss', () => {
    it('should parse SDEF file on first call', async () => {
      const bundleId = 'com.apple.notes';
      const sdefPath = '/path/to/Notes.sdef';
      const mockSDEFContent = '<?xml version="1.0"?><dictionary></dictionary>';
      const mockClasses = [{ name: 'note', code: 'notz', properties: [], elements: [] }];

      vi.mocked(fs.readFile).mockResolvedValue(mockSDEFContent);
      vi.mocked(fs.stat).mockResolvedValue({
        mtime: new Date('2024-01-01'),
      } as any);

      vi.mocked(parseSDEFClasses).mockReturnValue({
        classes: mockClasses,
        enumerations: [],
        classExtensions: [],
      });

      vi.mocked(generateTypeScriptTypes).mockReturnValue('');

      await cacheManager.getOrParse(bundleId, sdefPath);

      expect(fs.readFile).toHaveBeenCalledWith(sdefPath, 'utf-8');
      expect(parseSDEFClasses).toHaveBeenCalledWith(mockSDEFContent);
    });

    it('should generate TypeScript types on first parse', async () => {
      const bundleId = 'com.apple.calendar';
      const sdefPath = '/path/to/Calendar.sdef';
      const mockClasses = [
        {
          name: 'event',
          code: 'wrev',
          properties: [{ name: 'summary', code: 'summ', type: 'text' }],
          elements: [],
        },
      ];
      const mockTypeScript = 'export type Event = { summary: string };';

      vi.mocked(fs.readFile).mockResolvedValue('<?xml version="1.0"?><dictionary></dictionary>');
      vi.mocked(fs.stat).mockResolvedValue({
        mtime: new Date('2024-01-01'),
      } as any);

      vi.mocked(parseSDEFClasses).mockReturnValue({
        classes: mockClasses,
        enumerations: [],
        classExtensions: [],
      });

      vi.mocked(generateTypeScriptTypes).mockReturnValue(mockTypeScript);

      const result = await cacheManager.getOrParse(bundleId, sdefPath);

      expect(generateTypeScriptTypes).toHaveBeenCalled();
      expect(result.typescriptCode).toBe(mockTypeScript);
    });

    it('should cache result after first parse', async () => {
      const bundleId = 'com.apple.reminders';
      const sdefPath = '/path/to/Reminders.sdef';

      vi.mocked(fs.readFile).mockResolvedValue('<?xml version="1.0"?><dictionary></dictionary>');
      vi.mocked(fs.stat).mockResolvedValue({
        mtime: new Date('2024-01-01'),
      } as any);

      vi.mocked(parseSDEFClasses).mockReturnValue({
        classes: [],
        enumerations: [],
        classExtensions: [],
      });

      vi.mocked(generateTypeScriptTypes).mockReturnValue('');

      const result1 = await cacheManager.getOrParse(bundleId, sdefPath);
      const result2 = await cacheManager.getOrParse(bundleId, sdefPath);

      expect(result1).toEqual(result2);
      // File should only be read once due to caching
      expect(vi.mocked(fs.readFile)).toHaveBeenCalledTimes(1);
    });
  });

  describe('getOrParse() - stale cache', () => {
    it('should detect modified SDEF file and re-parse', async () => {
      vi.clearAllMocks();
      const bundleId = 'com.apple.contacts';
      const sdefPath = '/path/to/Contacts.sdef';

      // First call: SDEF at 2024-01-01
      vi.mocked(fs.readFile).mockResolvedValue('<?xml version="1.0"?><dictionary></dictionary>');
      let statCallCount = 0;
      vi.mocked(fs.stat).mockImplementation(async () => {
        statCallCount++;
        if (statCallCount === 1) {
          return { mtime: new Date('2024-01-01') } as any;
        } else {
          return { mtime: new Date('2024-02-01') } as any;
        }
      });

      let parseCallCount = 0;
      vi.mocked(parseSDEFClasses).mockImplementation(() => {
        parseCallCount++;
        if (parseCallCount === 1) {
          return {
            classes: [{ name: 'contact', code: 'cont', properties: [], elements: [] }],
            enumerations: [],
            classExtensions: [],
          };
        } else {
          return {
            classes: [{ name: 'group', code: 'grup', properties: [], elements: [] }],
            enumerations: [],
            classExtensions: [],
          };
        }
      });

      let typeGenCallCount = 0;
      vi.mocked(generateTypeScriptTypes).mockImplementation(() => {
        typeGenCallCount++;
        return typeGenCallCount === 1 ? 'type 1' : 'type 2';
      });

      await cacheManager.getOrParse(bundleId, sdefPath);

      // Second call: SDEF modified to 2024-02-01 (newer than cached lastParsed)
      const result = await cacheManager.getOrParse(bundleId, sdefPath);

      // Should have re-parsed (called parseSDEFClasses twice)
      expect(vi.mocked(parseSDEFClasses)).toHaveBeenCalledTimes(2);
      expect(result.classes[0].name).toBe('group');
      expect(result.typescriptCode).toBe('type 2');
    });

    it('should not re-parse when cache is still valid', async () => {
      vi.clearAllMocks();
      const bundleId = 'com.apple.photos';
      const sdefPath = '/path/to/Photos.sdef';
      const staticTime = new Date('2024-01-01');

      vi.mocked(fs.readFile).mockResolvedValue('<?xml version="1.0"?><dictionary></dictionary>');

      // Always return the same mtime (file not modified)
      vi.mocked(fs.stat).mockResolvedValue({
        mtime: staticTime,
      } as any);

      vi.mocked(parseSDEFClasses).mockReturnValue({
        classes: [],
        enumerations: [],
        classExtensions: [],
      });

      vi.mocked(generateTypeScriptTypes).mockReturnValue('');

      await cacheManager.getOrParse(bundleId, sdefPath);

      // Second call - file mtime hasn't changed
      await cacheManager.getOrParse(bundleId, sdefPath);

      // Should NOT have re-parsed (only 1 call)
      expect(vi.mocked(parseSDEFClasses)).toHaveBeenCalledTimes(1);
    });

    it('should assume cache is stale when SDEF mtime cannot be determined', async () => {
      vi.clearAllMocks();
      const bundleId = 'com.apple.music';
      const sdefPath = '/path/to/Music.sdef';

      vi.mocked(fs.readFile).mockResolvedValue('<?xml version="1.0"?><dictionary></dictionary>');

      // First call succeeds
      vi.mocked(fs.stat).mockResolvedValueOnce({
        mtime: new Date('2024-01-01'),
      } as any);

      vi.mocked(parseSDEFClasses).mockReturnValue({
        classes: [],
        enumerations: [],
        classExtensions: [],
      });

      vi.mocked(generateTypeScriptTypes).mockReturnValue('');

      await cacheManager.getOrParse(bundleId, sdefPath);

      // Second call: stat fails
      vi.mocked(fs.stat).mockRejectedValueOnce(new Error('Permission denied'));

      // Should attempt to re-parse (cache assumed stale)
      await cacheManager.getOrParse(bundleId, sdefPath);

      // parseSDEFClasses should be called twice (once for initial, once after stat failed)
      expect(vi.mocked(parseSDEFClasses)).toHaveBeenCalledTimes(2);
    });
  });

  describe('clear()', () => {
    it('should clear specific bundle ID cache', async () => {
      const bundleId1 = 'com.apple.finder';
      const bundleId2 = 'com.apple.safari';

      vi.mocked(fs.readFile).mockResolvedValue('<?xml version="1.0"?><dictionary></dictionary>');
      vi.mocked(fs.stat).mockResolvedValue({
        mtime: new Date('2024-01-01'),
      } as any);

      vi.mocked(parseSDEFClasses).mockReturnValue({
        classes: [],
        enumerations: [],
        classExtensions: [],
      });

      vi.mocked(generateTypeScriptTypes).mockReturnValue('');

      await cacheManager.getOrParse(bundleId1, '/path/to/Finder.sdef');
      await cacheManager.getOrParse(bundleId2, '/path/to/Safari.sdef');

      expect(cacheManager.size()).toBe(2);

      cacheManager.clear(bundleId1);

      expect(cacheManager.size()).toBe(1);
      // Verify that bundleId1 is gone but bundleId2 remains by attempting to get it
      // (would need to re-parse if cache was cleared)
      vi.mocked(parseSDEFClasses).mockReturnValue({
        classes: [{ name: 'tab', code: 'tabl', properties: [], elements: [] }],
        enumerations: [],
        classExtensions: [],
      });

      const result = await cacheManager.getOrParse(bundleId1, '/path/to/Finder.sdef');
      expect(result.classes[0].name).toBe('tab'); // Re-parsed with new data
    });

    it('should clear all caches when called without parameter', async () => {
      const bundleIds = [
        'com.apple.finder',
        'com.apple.safari',
        'com.apple.mail',
      ];

      vi.mocked(fs.readFile).mockResolvedValue('<?xml version="1.0"?><dictionary></dictionary>');
      vi.mocked(fs.stat).mockResolvedValue({
        mtime: new Date('2024-01-01'),
      } as any);

      vi.mocked(parseSDEFClasses).mockReturnValue({
        classes: [],
        enumerations: [],
        classExtensions: [],
      });

      vi.mocked(generateTypeScriptTypes).mockReturnValue('');

      for (const bundleId of bundleIds) {
        await cacheManager.getOrParse(bundleId, `/path/to/${bundleId}.sdef`);
      }

      expect(cacheManager.size()).toBe(3);

      cacheManager.clear();

      expect(cacheManager.size()).toBe(0);
    });

    it('should allow re-parsing after clear', async () => {
      const bundleId = 'com.apple.reminders';

      vi.mocked(fs.readFile).mockResolvedValue('<?xml version="1.0"?><dictionary></dictionary>');
      vi.mocked(fs.stat).mockResolvedValue({
        mtime: new Date('2024-01-01'),
      } as any);

      vi.mocked(parseSDEFClasses).mockReturnValue({
        classes: [{ name: 'reminder', code: 'remr', properties: [], elements: [] }],
        enumerations: [],
        classExtensions: [],
      });

      vi.mocked(generateTypeScriptTypes).mockReturnValue('original');

      const result1 = await cacheManager.getOrParse(bundleId, '/path/to/Reminders.sdef');
      expect(result1.classes[0].name).toBe('reminder');

      cacheManager.clear(bundleId);

      vi.mocked(parseSDEFClasses).mockReturnValue({
        classes: [{ name: 'task', code: 'task', properties: [], elements: [] }],
        enumerations: [],
        classExtensions: [],
      });

      vi.mocked(generateTypeScriptTypes).mockReturnValue('updated');

      const result2 = await cacheManager.getOrParse(bundleId, '/path/to/Reminders.sdef');
      expect(result2.classes[0].name).toBe('task');
      expect(result2.typescriptCode).toBe('updated');
    });
  });

  describe('size()', () => {
    it('should return 0 for empty cache', () => {
      expect(cacheManager.size()).toBe(0);
    });

    it('should return correct count after parsing', async () => {
      vi.mocked(fs.readFile).mockResolvedValue('<?xml version="1.0"?><dictionary></dictionary>');
      vi.mocked(fs.stat).mockResolvedValue({
        mtime: new Date('2024-01-01'),
      } as any);

      vi.mocked(parseSDEFClasses).mockReturnValue({
        classes: [],
        enumerations: [],
        classExtensions: [],
      });

      vi.mocked(generateTypeScriptTypes).mockReturnValue('');

      expect(cacheManager.size()).toBe(0);

      await cacheManager.getOrParse('com.apple.finder', '/path/to/Finder.sdef');
      expect(cacheManager.size()).toBe(1);

      await cacheManager.getOrParse('com.apple.safari', '/path/to/Safari.sdef');
      expect(cacheManager.size()).toBe(2);

      await cacheManager.getOrParse('com.apple.mail', '/path/to/Mail.sdef');
      expect(cacheManager.size()).toBe(3);
    });

    it('should update after clear', async () => {
      vi.mocked(fs.readFile).mockResolvedValue('<?xml version="1.0"?><dictionary></dictionary>');
      vi.mocked(fs.stat).mockResolvedValue({
        mtime: new Date('2024-01-01'),
      } as any);

      vi.mocked(parseSDEFClasses).mockReturnValue({
        classes: [],
        enumerations: [],
        classExtensions: [],
      });

      vi.mocked(generateTypeScriptTypes).mockReturnValue('');

      await cacheManager.getOrParse('com.apple.finder', '/path/to/Finder.sdef');
      await cacheManager.getOrParse('com.apple.safari', '/path/to/Safari.sdef');

      expect(cacheManager.size()).toBe(2);

      cacheManager.clear('com.apple.finder');
      expect(cacheManager.size()).toBe(1);

      cacheManager.clear();
      expect(cacheManager.size()).toBe(0);
    });
  });

  describe('error handling', () => {
    it('should throw error when SDEF file cannot be read', async () => {
      const bundleId = 'com.apple.finder';
      const sdefPath = '/nonexistent/path/Finder.sdef';

      vi.mocked(fs.readFile).mockRejectedValue(
        new Error('ENOENT: no such file or directory')
      );

      await expect(
        cacheManager.getOrParse(bundleId, sdefPath)
      ).rejects.toThrow();
    });

    it('should handle file stat errors gracefully', async () => {
      vi.clearAllMocks();
      const bundleId = 'com.apple.safari';
      const sdefPath = '/path/to/Safari.sdef';

      vi.mocked(fs.readFile).mockResolvedValue('<?xml version="1.0"?><dictionary></dictionary>');

      // First call succeeds
      vi.mocked(fs.stat).mockResolvedValueOnce({
        mtime: new Date('2024-01-01'),
      } as any);

      vi.mocked(parseSDEFClasses).mockReturnValue({
        classes: [{ name: 'window', code: 'cwin', properties: [], elements: [] }],
        enumerations: [],
        classExtensions: [],
      });

      vi.mocked(generateTypeScriptTypes).mockReturnValue('type 1');

      await cacheManager.getOrParse(bundleId, sdefPath);

      // Second call: stat fails
      vi.mocked(fs.stat).mockRejectedValueOnce(
        new Error('Permission denied')
      );

      vi.mocked(parseSDEFClasses).mockReturnValue({
        classes: [{ name: 'tab', code: 'tabl', properties: [], elements: [] }],
        enumerations: [],
        classExtensions: [],
      });

      vi.mocked(generateTypeScriptTypes).mockReturnValue('type 2');

      const result = await cacheManager.getOrParse(bundleId, sdefPath);

      // Should return the new data (re-parsed after stat error)
      expect(result.classes[0].name).toBe('tab');
    });

    it('should throw error when SDEF parsing fails', async () => {
      const bundleId = 'com.apple.mail';
      const sdefPath = '/path/to/Mail.sdef';

      vi.mocked(fs.readFile).mockResolvedValue('invalid xml');
      vi.mocked(fs.stat).mockResolvedValue({
        mtime: new Date('2024-01-01'),
      } as any);

      vi.mocked(parseSDEFClasses).mockImplementation(() => {
        throw new Error('XML parse error');
      });

      await expect(
        cacheManager.getOrParse(bundleId, sdefPath)
      ).rejects.toThrow('XML parse error');
    });

    it('should throw error when type generation fails', async () => {
      const bundleId = 'com.apple.notes';
      const sdefPath = '/path/to/Notes.sdef';

      vi.mocked(fs.readFile).mockResolvedValue('<?xml version="1.0"?><dictionary></dictionary>');
      vi.mocked(fs.stat).mockResolvedValue({
        mtime: new Date('2024-01-01'),
      } as any);

      vi.mocked(parseSDEFClasses).mockReturnValue({
        classes: [],
        enumerations: [],
        classExtensions: [],
      });

      vi.mocked(generateTypeScriptTypes).mockImplementation(() => {
        throw new Error('Type generation failed');
      });

      await expect(
        cacheManager.getOrParse(bundleId, sdefPath)
      ).rejects.toThrow('Type generation failed');
    });
  });

  describe('complex scenarios', () => {
    it('should handle multiple different bundle IDs independently', async () => {
      const bundleIds = [
        'com.apple.finder',
        'com.apple.safari',
        'com.apple.mail',
      ];

      vi.mocked(fs.readFile).mockResolvedValue('<?xml version="1.0"?><dictionary></dictionary>');
      vi.mocked(fs.stat).mockResolvedValue({
        mtime: new Date('2024-01-01'),
      } as any);

      const mockClassesMap: Record<string, any> = {
        'com.apple.finder': { name: 'folder', code: 'cfol', properties: [], elements: [] },
        'com.apple.safari': { name: 'tab', code: 'tabl', properties: [], elements: [] },
        'com.apple.mail': { name: 'message', code: 'msg ', properties: [], elements: [] },
      };

      // Manually set up return values for each call
      let callCount = 0;
      vi.mocked(parseSDEFClasses).mockImplementation(() => {
        const classes = [Object.values(mockClassesMap)[callCount]];
        callCount++;
        return {
          classes: classes as any,
          enumerations: [],
          classExtensions: [],
        };
      });

      vi.mocked(generateTypeScriptTypes).mockImplementation((classes: any[]) => {
        return `export type ${classes[0]?.name || 'Unknown'} = {};`;
      });

      for (let i = 0; i < bundleIds.length; i++) {
        await cacheManager.getOrParse(bundleIds[i], `/path/to/${bundleIds[i]}.sdef`);
      }

      expect(cacheManager.size()).toBe(3);
      expect(vi.mocked(parseSDEFClasses)).toHaveBeenCalledTimes(3);
    });

    it('should preserve timestamps accurately', async () => {
      const bundleId = 'com.apple.contacts';
      const sdefPath = '/path/to/Contacts.sdef';
      const timestamp1 = new Date('2024-01-01T12:00:00Z');

      vi.mocked(fs.readFile).mockResolvedValue('<?xml version="1.0"?><dictionary></dictionary>');
      vi.mocked(fs.stat).mockResolvedValueOnce({
        mtime: timestamp1,
      } as any);

      vi.mocked(parseSDEFClasses).mockReturnValue({
        classes: [],
        enumerations: [],
        classExtensions: [],
      });

      vi.mocked(generateTypeScriptTypes).mockReturnValue('');

      const result = await cacheManager.getOrParse(bundleId, sdefPath);

      expect(result.lastParsed).toBeInstanceOf(Date);
      // lastParsed should be set to the SDEF file's mtime (for staleness detection)
      expect(result.lastParsed.getTime()).toBe(timestamp1.getTime());
    });
  });
});
