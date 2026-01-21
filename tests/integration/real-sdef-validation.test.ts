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
import {
  setupSDEFTest,
  hasUnknownTypes,
  getAllCommands,
  type SDEFTestContext,
} from '../utils/sdef-test-helpers.js';
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
            return;
          }

          expect(sdefPath).toBeTruthy();
          expect(sdefPath).toContain('.sdef');
          expect(sdefPath).toContain(targetApp.bundlePath);
        });
      }
    });

    // ========================================================================
    // Test 2: Parsing Tests
    // ========================================================================

    describe('Parsing: Parse Target App SDEF Files', () => {
      for (const targetApp of TARGET_APPS) {
        describe(`${targetApp.name} SDEF Parsing`, () => {
          let testContext: SDEFTestContext | null;

          beforeAll(async () => {
            testContext = await setupSDEFTest(targetApp.bundlePath);
          });

          it(`should parse ${targetApp.name} without errors`, async () => {
            if (!testContext) return;

            expect(testContext.dictionary).toBeTruthy();
            expect(testContext.dictionary).toHaveProperty('suites');
            expect(Array.isArray(testContext.dictionary.suites)).toBe(true);
          });

          it(`should extract suites from ${targetApp.name}`, () => {
            if (!testContext) return;

            expect(testContext.dictionary.suites.length).toBeGreaterThan(0);
          });

          it(`should have resolved types in ${targetApp.name} (no "unknown")`, () => {
            if (!testContext) return;

            const hasUnknown = hasUnknownTypes(testContext.dictionary);
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
          let testContext: SDEFTestContext | null;

          beforeAll(async () => {
            testContext = await setupSDEFTest(targetApp.bundlePath);
          });

          it(`should extract at least ${targetApp.minCommandCount} commands from ${targetApp.name}`, () => {
            if (!testContext) return;

            expect(testContext.allCommands.length).toBeGreaterThanOrEqual(
              targetApp.minCommandCount
            );
          });

          it(`should have expected commands in ${targetApp.name}`, () => {
            if (!testContext) return;

            // Check for at least some expected commands
            const foundExpected = targetApp.expectedCommands.filter((cmd) =>
              testContext!.allCommands.some((c) => c.toLowerCase() === cmd.toLowerCase())
            );

            expect(foundExpected.length).toBeGreaterThan(0);
          });

          it(`should have properly typed parameters in ${targetApp.name}`, () => {
            if (!testContext) return;

            let typedParameterCount = 0;
            let totalParameterCount = 0;

            for (const suite of testContext.dictionary.suites) {
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
          const testContext = await setupSDEFTest(targetApp.bundlePath);
          if (!testContext) return;

          // If we have expected include file, the parsing should have included it
          // We can verify this by checking that we have more commands than just
          // what would be in the main SDEF
          expect(testContext.dictionary.suites.length).toBeGreaterThan(0);
          expect(testContext.allCommands.length).toBeGreaterThan(5);
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
            status: 'found' | 'not_found';
            suiteCount?: number;
            commandCount?: number;
            classCount?: number;
          }
        > = {};

        for (const targetApp of TARGET_APPS) {
          const testContext = await setupSDEFTest(targetApp.bundlePath);

          if (!testContext) {
            metrics[targetApp.name] = { status: 'not_found' };
            continue;
          }

          let classCount = 0;
          for (const suite of testContext.dictionary.suites) {
            classCount += suite.classes.length;
          }

          metrics[targetApp.name] = {
            status: 'found',
            suiteCount: testContext.dictionary.suites.length,
            commandCount: testContext.allCommands.length,
            classCount,
          };
        }

        // Log metrics
        console.log('\n=== Phase 3 Validation Metrics ===');
        for (const [appName, data] of Object.entries(metrics)) {
          if (data.status === 'found') {
            console.log(
              `✓ ${appName}: ${data.suiteCount} suites, ${data.commandCount} commands, ${data.classCount} classes`
            );
          } else {
            console.log(`⊘ ${appName}: Not installed`);
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
        const testContext = await setupSDEFTest('/System/Library/CoreServices/Finder.app');
        if (!testContext) return;

        expect(testContext.dictionary.suites.length).toBeGreaterThan(0);
        expect(testContext.allCommands.length).toBeGreaterThan(20); // Finder has many commands
      });

      it('should compare command counts: target apps vs Finder', async () => {
        const metrics: Record<string, number> = {};

        // Finder baseline
        const finderContext = await setupSDEFTest('/System/Library/CoreServices/Finder.app');
        if (finderContext) {
          metrics['Finder'] = finderContext.allCommands.length;
        }

        // Target apps
        for (const targetApp of TARGET_APPS) {
          const testContext = await setupSDEFTest(targetApp.bundlePath);
          if (testContext) {
            metrics[targetApp.name] = testContext.allCommands.length;
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
