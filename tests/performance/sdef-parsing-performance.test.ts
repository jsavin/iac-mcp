/**
 * SDEF Parsing Performance Tests
 *
 * Ensures that SDEF parsing performance remains within acceptable bounds
 * and that lenient mode doesn't introduce significant overhead.
 */

import { describe, it, expect } from 'vitest';
import { resolve } from 'path';
import { SDEFParser } from '../../src/jitd/discovery/parse-sdef.js';
import { isMacOS } from '../utils/test-helpers.js';

describe.skipIf(!isMacOS())('SDEF Parsing Performance', () => {
  const finderSdefPath =
    '/System/Library/CoreServices/Finder.app/Contents/Resources/Finder.sdef';
  const strictCompatibleSdefPath = resolve(
    __dirname,
    '../fixtures/sdef/strict-mode-compatible.sdef'
  );

  it('should parse large SDEF files within performance budget', async () => {
    // Use lenient mode since Finder.sdef has complex types that strict mode rejects
    const parser = new SDEFParser({ mode: 'lenient' });

    const startTime = performance.now();
    await parser.parse(finderSdefPath);
    const duration = performance.now() - startTime;

    // Should complete within 5 seconds
    expect(duration).toBeLessThan(5000);

    // Log for monitoring (visible in CI)
    console.log(
      `Finder.sdef parsing time (lenient): ${duration.toFixed(2)}ms`
    );
  });

  it('should have minimal performance overhead in lenient mode vs strict mode', async () => {
    // Use strict-mode-compatible.sdef which works with both modes
    // Run multiple iterations to get stable measurements

    // Warmup: Parse once to JIT compile, load file into OS cache, etc.
    const warmupParser = new SDEFParser({ mode: 'strict' });
    await warmupParser.parse(strictCompatibleSdefPath);

    // Benchmark strict mode (10 iterations for stable average)
    const strictTimes: number[] = [];
    for (let i = 0; i < 10; i++) {
      const strictParser = new SDEFParser({ mode: 'strict' });
      const start = performance.now();
      await strictParser.parse(strictCompatibleSdefPath);
      strictTimes.push(performance.now() - start);
    }
    const strictAverage =
      strictTimes.reduce((a, b) => a + b) / strictTimes.length;

    // Benchmark lenient mode (10 iterations for stable average)
    const lenientTimes: number[] = [];
    for (let i = 0; i < 10; i++) {
      const lenientParser = new SDEFParser({ mode: 'lenient' });
      const start = performance.now();
      await lenientParser.parse(strictCompatibleSdefPath);
      lenientTimes.push(performance.now() - start);
    }
    const lenientAverage =
      lenientTimes.reduce((a, b) => a + b) / lenientTimes.length;

    // Lenient mode overhead should be < 20%
    const overhead = (lenientAverage - strictAverage) / strictAverage;
    expect(overhead).toBeLessThan(0.2);

    console.log(`Strict mode average: ${strictAverage.toFixed(2)}ms`);
    console.log(`Lenient mode average: ${lenientAverage.toFixed(2)}ms`);
    console.log(`Overhead: ${(overhead * 100).toFixed(1)}%`);
  });

  it('should handle repeated parsing without memory leaks', async () => {
    const parser = new SDEFParser({ mode: 'lenient' });

    // Parse 10 times
    const times: number[] = [];
    for (let i = 0; i < 10; i++) {
      const start = performance.now();
      await parser.parse(finderSdefPath);
      times.push(performance.now() - start);
    }

    // Average should be consistent (no memory leak causing slowdown)
    const average = times.reduce((a, b) => a + b) / times.length;
    const lastThree = times.slice(-3).reduce((a, b) => a + b) / 3;

    // Last 3 iterations shouldn't be >50% slower than average
    expect(lastThree).toBeLessThan(average * 1.5);

    console.log(`Average parse time: ${average.toFixed(2)}ms`);
    console.log(`Last 3 average: ${lastThree.toFixed(2)}ms`);
  });
});
