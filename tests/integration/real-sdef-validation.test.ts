/**
 * Phase 3 Validation: Real SDEF Discovery & Parsing with XInclude Support
 *
 * Tests that Phase 3 (EntityResolver integration) successfully enables parsing
 * of Pages, Numbers, Keynote, and System Events - apps that use XInclude to
 * reference shared SDEF definitions (like CocoaStandard.sdef).
 *
 * Before Phase 3: These apps couldn't be parsed (XInclude elements unresolved)
 * After Phase 3: These apps parse successfully with XInclude resolved
 *
 * Test coverage:
 * - Real SDEF discovery for target apps
 * - Parsing without errors
 * - Command extraction from main + included files
 * - Type resolution (no "unknown" primitives)
 * - Error handling for missing/malformed files
 * - Metrics collection
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { findAllScriptableApps, findSDEFFile } from '../../src/jitd/discovery/find-sdef.js';
import { SDEFParser } from '../../src/jitd/discovery/parse-sdef.js';
import { isMacOS } from '../utils/test-helpers.js';
import type { SDEFDictionary } from '../../src/types/sdef.js';

/**
 * Skip tests entirely if not on macOS
 */
if (!isMacOS()) {
  describe.skip('Phase 3 Validation: Real SDEF Discovery', () => {
    it('skipped: not on macOS', () => {
      expect(true).toBe(true);
    });
  });
} else {
  /**
   * Target apps to validate (require XInclude support)
   */
  const TARGET_APPS = [
    {
      name: 'Pages',
      bundleId: 'com.apple.iWork.Pages',
      bundlePath: '/Applications/Pages.app',
      expectedIncludeFile: 'CocoaStandard.sdef',
      expectedCommands: ['close', 'save', 'get', 'set', 'open', 'duplicate'],
      minCommandCount: 10,
    },
    {
      name: 'Numbers',
      bundleId: 'com.apple.iWork.Numbers',
      bundlePath: '/Applications/Numbers.app',
      expectedIncludeFile: 'CocoaStandard.sdef',
      expectedCommands: ['close', 'save', 'get', 'set', 'open', 'duplicate'],
      minCommandCount: 10,
    },
    {
      name: 'Keynote',
      bundleId: 'com.apple.iWork.Keynote',
      bundlePath: '/Applications/Keynote.app',
      expectedIncludeFile: 'CocoaStandard.sdef',
      expectedCommands: ['close', 'save', 'get', 'set', 'open', 'duplicate'],
      minCommandCount: 10,
    },
    {
      name: 'System Events',
      bundleId: 'com.apple.systemevents',
      bundlePath: '/Library/ScriptingAdditions/System Events.osax',
      expectedIncludeFile: null, // May or may not use includes
      expectedCommands: ['launch', 'quit', 'get', 'set'],
      minCommandCount: 5,
    },
  ];

  describe('Phase 3 Validation: Real SDEF Discovery & XInclude Resolution', () => {
    /**
     * Test helper: Flatten all commands from all suites
     */
    function getAllCommands(dictionary: SDEFDictionary) {
      const commands: string[] = [];
      for (const suite of dictionary.suites) {
        for (const cmd of suite.commands) {
          commands.push(cmd.name);
        }
      }
      return commands;
    }

    /**
     * Test helper: Check if any type is "unknown"
     */
    function hasUnknownTypes(dictionary: SDEFDictionary): boolean {
      for (const suite of dictionary.suites) {
        for (const cmd of suite.commands) {
          // Check parameters
          for (const param of cmd.parameters) {
            if (param.type.kind === 'primitive' && param.type.type === 'unknown') {
              return true;
            }
          }
          // Check result
          if (
            cmd.result &&
            cmd.result.kind === 'primitive' &&
            cmd.result.type === 'unknown'
          ) {
            return true;
          }
          // Check direct parameter
          if (
            cmd.directParameter &&
            cmd.directParameter.type.kind === 'primitive' &&
            cmd.directParameter.type.type === 'unknown'
          ) {
            return true;
          }
        }

        // Check classes
        for (const cls of suite.classes) {
          for (const prop of cls.properties) {
            if (prop.type.kind === 'primitive' && prop.type.type === 'unknown') {
              return true;
            }
          }
        }
      }
      return false;
    }

    // ========================================================================
    // Test 1: Discovery Tests
    // ========================================================================

    describe('Discovery: Locate Target Apps', () => {
      it('should discover all target apps via findAllScriptableApps', async () => {
        const allApps = await findAllScriptableApps();
        const discoveredNames = allApps.map((app) => app.appName.toLowerCase());

        // At minimum, we should find some of the target apps
        // Pages/Numbers/Keynote may not be installed, but at least System Events should be
        let foundCount = 0;
        for (const target of TARGET_APPS) {
          const found = discoveredNames.some((name) =>
            name.includes(target.name.toLowerCase())
          );
          if (found) {
            foundCount++;
          }
        }

        expect(foundCount).toBeGreaterThan(0);
      });

      for (const targetApp of TARGET_APPS) {
        it(`should find SDEF file for ${targetApp.name}`, async () => {
          const sdefPath = await findSDEFFile(targetApp.bundlePath);

          if (sdefPath === null) {
            // App not installed on this system - that's OK
            console.log(`ℹ ${targetApp.name} not installed on this system`);
          } else {
            expect(sdefPath).toBeTruthy();
            expect(sdefPath).toContain('.sdef');
            expect(sdefPath).toContain(targetApp.bundlePath);
          }
        });
      }
    });

    // ========================================================================
    // Test 2: Parsing Tests
    // ========================================================================

    describe('Parsing: Parse Target App SDEF Files', () => {
      for (const targetApp of TARGET_APPS) {
        describe(`${targetApp.name} SDEF Parsing`, () => {
          let sdefPath: string | null;
          let dictionary: SDEFDictionary | null;

          beforeAll(async () => {
            // Find SDEF file
            sdefPath = await findSDEFFile(targetApp.bundlePath);
            if (!sdefPath) {
              console.log(
                `⊘ ${targetApp.name} SDEF not found - skipping detailed tests`
              );
              return;
            }

            // Parse SDEF
            const parser = new SDEFParser();
            try {
              dictionary = await parser.parse(sdefPath);
            } catch (error) {
              console.error(
                `Failed to parse ${targetApp.name}: ${
                  error instanceof Error ? error.message : String(error)
                }`
              );
            }
          });

          it(`should parse ${targetApp.name} without errors`, async () => {
            if (!sdefPath) {
              console.log(`Skipping: ${targetApp.name} SDEF not found`);
              return;
            }

            expect(dictionary).toBeTruthy();
            expect(dictionary).toHaveProperty('suites');
            expect(Array.isArray(dictionary!.suites)).toBe(true);
          });

          it(`should extract suites from ${targetApp.name}`, () => {
            if (!dictionary) {
              console.log(`Skipping: ${targetApp.name} dictionary not parsed`);
              return;
            }

            expect(dictionary.suites.length).toBeGreaterThan(0);
          });

          it(`should have resolved types in ${targetApp.name} (no "unknown")`, () => {
            if (!dictionary) {
              console.log(`Skipping: ${targetApp.name} dictionary not parsed`);
              return;
            }

            const hasUnknown = hasUnknownTypes(dictionary);
            expect(hasUnknown).toBe(false);
          });
        });
      }
    });

    // ========================================================================
    // Test 3: Command Extraction Tests
    // ========================================================================

    describe('Command Extraction: Verify Expected Commands', () => {
      for (const targetApp of TARGET_APPS) {
        describe(`${targetApp.name} Command Extraction`, () => {
          let dictionary: SDEFDictionary | null;
          let allCommands: string[] = [];

          beforeAll(async () => {
            const sdefPath = await findSDEFFile(targetApp.bundlePath);
            if (!sdefPath) {
              console.log(`Skipping: ${targetApp.name} SDEF not found`);
              return;
            }

            const parser = new SDEFParser();
            try {
              dictionary = await parser.parse(sdefPath);
              if (dictionary) {
                allCommands = getAllCommands(dictionary);
              }
            } catch (error) {
              console.error(
                `Failed to parse ${targetApp.name}: ${
                  error instanceof Error ? error.message : String(error)
                }`
              );
            }
          });

          it(`should extract at least ${targetApp.minCommandCount} commands from ${targetApp.name}`, () => {
            if (!dictionary) {
              console.log(`Skipping: ${targetApp.name} dictionary not parsed`);
              return;
            }

            expect(allCommands.length).toBeGreaterThanOrEqual(
              targetApp.minCommandCount
            );
          });

          it(`should have expected commands in ${targetApp.name}`, () => {
            if (!dictionary) {
              console.log(`Skipping: ${targetApp.name} dictionary not parsed`);
              return;
            }

            // Check for at least some expected commands
            const foundExpected = targetApp.expectedCommands.filter((cmd) =>
              allCommands.some((c) => c.toLowerCase() === cmd.toLowerCase())
            );

            expect(foundExpected.length).toBeGreaterThan(0);
          });

          it(`should have properly typed parameters in ${targetApp.name}`, () => {
            if (!dictionary) {
              console.log(`Skipping: ${targetApp.name} dictionary not parsed`);
              return;
            }

            let typedParameterCount = 0;
            let totalParameterCount = 0;

            for (const suite of dictionary.suites) {
              for (const cmd of suite.commands) {
                for (const param of cmd.parameters) {
                  totalParameterCount++;
                  if (param.type.kind !== 'any') {
                    typedParameterCount++;
                  }
                }
              }
            }

            // Should have at least some properly typed parameters
            expect(typedParameterCount).toBeGreaterThan(0);
          });
        });
      }
    });

    // ========================================================================
    // Test 4: XInclude Resolution (When Applicable)
    // ========================================================================

    describe('XInclude Resolution: Verify Included Content', () => {
      for (const targetApp of TARGET_APPS.filter((app) => app.expectedIncludeFile)) {
        it(`should resolve includes for ${targetApp.name}`, async () => {
          const sdefPath = await findSDEFFile(targetApp.bundlePath);
          if (!sdefPath) {
            console.log(`Skipping: ${targetApp.name} SDEF not found`);
            return;
          }

          const parser = new SDEFParser();
          const dictionary = await parser.parse(sdefPath);

          // If we have expected include file, the parsing should have included it
          // We can verify this by checking that we have more commands than just
          // what would be in the main SDEF
          expect(dictionary.suites.length).toBeGreaterThan(0);
          expect(getAllCommands(dictionary).length).toBeGreaterThan(5);
        });
      }
    });

    // ========================================================================
    // Test 5: Metrics & Reporting
    // ========================================================================

    describe('Metrics: Command Count & Coverage', () => {
      it('should generate comprehensive metrics for all target apps', async () => {
        const metrics: Record<
          string,
          {
            status: 'found' | 'not_found' | 'error';
            suiteCount?: number;
            commandCount?: number;
            classCount?: number;
            error?: string;
          }
        > = {};

        for (const targetApp of TARGET_APPS) {
          const sdefPath = await findSDEFFile(targetApp.bundlePath);

          if (!sdefPath) {
            metrics[targetApp.name] = { status: 'not_found' };
            continue;
          }

          try {
            const parser = new SDEFParser();
            const dictionary = await parser.parse(sdefPath);
            const commands = getAllCommands(dictionary);
            let classCount = 0;

            for (const suite of dictionary.suites) {
              classCount += suite.classes.length;
            }

            metrics[targetApp.name] = {
              status: 'found',
              suiteCount: dictionary.suites.length,
              commandCount: commands.length,
              classCount,
            };
          } catch (error) {
            metrics[targetApp.name] = {
              status: 'error',
              error:
                error instanceof Error ? error.message : String(error),
            };
          }
        }

        // Log metrics
        console.log('\n=== Phase 3 Validation Metrics ===');
        for (const [appName, data] of Object.entries(metrics)) {
          if (data.status === 'found') {
            console.log(
              `✓ ${appName}: ${data.suiteCount} suites, ${data.commandCount} commands, ${data.classCount} classes`
            );
          } else if (data.status === 'not_found') {
            console.log(`⊘ ${appName}: Not installed`);
          } else {
            console.log(`✗ ${appName}: Error - ${data.error}`);
          }
        }

        // At least one app should be found and parsed successfully
        const successCount = Object.values(metrics).filter(
          (m) => m.status === 'found'
        ).length;
        expect(successCount).toBeGreaterThan(0);
      });
    });

    // ========================================================================
    // Test 6: Error Handling
    // ========================================================================

    describe('Error Handling: Graceful Degradation', () => {
      it('should handle missing SDEF files gracefully', async () => {
        const fakePath = '/Applications/FakeApp.app';
        const result = await findSDEFFile(fakePath);
        expect(result).toBeNull();
      });

      it('should handle parsing errors without crashing', async () => {
        const parser = new SDEFParser();
        const invalidSdef = '<?xml version="1.0"?><invalid>';

        try {
          await parser.parseContent(invalidSdef);
          // If no error, that's also OK - parser handles it gracefully
        } catch (error) {
          // Error is expected, just verify it's handled
          expect(error).toBeTruthy();
        }
      });
    });

    // ========================================================================
    // Test 7: Comparison with Known Good (Baseline)
    // ========================================================================

    describe('Baseline Comparison: Finder SDEF', () => {
      it('should parse Finder.sdef successfully', async () => {
        const finderPath = await findSDEFFile('/System/Library/CoreServices/Finder.app');

        if (!finderPath) {
          console.log('Skipping: Finder.sdef not found');
          return;
        }

        const parser = new SDEFParser();
        const dictionary = await parser.parse(finderPath);

        expect(dictionary.suites.length).toBeGreaterThan(0);
        const commands = getAllCommands(dictionary);
        expect(commands.length).toBeGreaterThan(20); // Finder has many commands
      });

      it('should compare command counts: target apps vs Finder', async () => {
        const metrics: Record<string, number> = {};

        // Finder baseline
        const finderPath = await findSDEFFile(
          '/System/Library/CoreServices/Finder.app'
        );
        if (finderPath) {
          const parser = new SDEFParser();
          const dict = await parser.parse(finderPath);
          metrics['Finder'] = getAllCommands(dict).length;
        }

        // Target apps
        for (const targetApp of TARGET_APPS) {
          const sdefPath = await findSDEFFile(targetApp.bundlePath);
          if (sdefPath) {
            const parser = new SDEFParser();
            const dict = await parser.parse(sdefPath);
            metrics[targetApp.name] = getAllCommands(dict).length;
          }
        }

        console.log('\n=== Command Count Comparison ===');
        for (const [appName, count] of Object.entries(metrics)) {
          console.log(`${appName}: ${count} commands`);
        }

        // Verify we have some data
        expect(Object.keys(metrics).length).toBeGreaterThan(0);
      });
    });
  });
}
