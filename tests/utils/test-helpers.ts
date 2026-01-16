/**
 * Test utilities and helper functions
 *
 * Shared utilities for SDEF parser tests
 */

import { join } from 'path';
import { readFile } from 'fs/promises';

/**
 * Get the path to a test fixture file
 */
export function getFixturePath(...segments: string[]): string {
  return join(process.cwd(), 'tests', 'fixtures', ...segments);
}

/**
 * Load a test fixture file as a string
 */
export async function loadFixture(...segments: string[]): Promise<string> {
  const path = getFixturePath(...segments);
  return readFile(path, 'utf-8');
}

/**
 * Load the minimal valid SDEF fixture
 */
export async function loadMinimalValidSDEF(): Promise<string> {
  return loadFixture('sdef', 'minimal-valid.sdef');
}

/**
 * Load the malformed SDEF fixture
 */
export async function loadMalformedSDEF(): Promise<string> {
  return loadFixture('sdef', 'malformed.sdef');
}

/**
 * Load Finder.sdef if available
 * Returns null if not accessible (e.g., not on macOS)
 */
export async function loadFinderSDEF(): Promise<string | null> {
  try {
    const finderPath = '/System/Library/CoreServices/Finder.app/Contents/Resources/Finder.sdef';
    return await readFile(finderPath, 'utf-8');
  } catch (error) {
    return null;
  }
}

/**
 * Check if running on macOS
 */
export function isMacOS(): boolean {
  return process.platform === 'darwin';
}

/**
 * Skip test if not on macOS
 */
export function skipIfNotMacOS(testFn: () => void | Promise<void>): void | Promise<void> {
  if (!isMacOS()) {
    console.log('Skipping test: not on macOS');
    return;
  }
  return testFn();
}

/**
 * Create a minimal SDEF XML string for testing
 */
export function createMinimalSDEF(options: {
  title?: string;
  suiteName?: string;
  suiteCode?: string;
  commandName?: string;
  commandCode?: string;
} = {}): string {
  const {
    title = 'Test App',
    suiteName = 'Test Suite',
    suiteCode = 'TEST',
    commandName = 'test',
    commandCode = 'test',
  } = options;

  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE dictionary SYSTEM "file://localhost/System/Library/DTDs/sdef.dtd">
<dictionary title="${title}">
  <suite name="${suiteName}" code="${suiteCode}">
    <command name="${commandName}" code="${commandCode}">
      <direct-parameter type="text" description="test parameter"/>
    </command>
  </suite>
</dictionary>`;
}

/**
 * Create a command SDEF fragment for testing
 */
export function createCommandFragment(options: {
  name: string;
  code: string;
  description?: string;
  parameters?: Array<{
    name: string;
    code: string;
    type: string;
    optional?: boolean;
  }>;
  resultType?: string;
}): string {
  const { name, code, description, parameters = [], resultType } = options;

  let xml = `<command name="${name}" code="${code}"`;
  if (description) {
    xml += ` description="${description}"`;
  }
  xml += '>\n';

  // Add parameters
  for (const param of parameters) {
    xml += `  <parameter name="${param.name}" code="${param.code}" type="${param.type}"`;
    if (param.optional) {
      xml += ' optional="yes"';
    }
    xml += '/>\n';
  }

  // Add result
  if (resultType) {
    xml += `  <result type="${resultType}"/>\n`;
  }

  xml += '</command>';
  return xml;
}

/**
 * Create a class SDEF fragment for testing
 */
export function createClassFragment(options: {
  name: string;
  code: string;
  description?: string;
  properties?: Array<{
    name: string;
    code: string;
    type: string;
    access: 'r' | 'w' | 'rw';
  }>;
}): string {
  const { name, code, description, properties = [] } = options;

  let xml = `<class name="${name}" code="${code}"`;
  if (description) {
    xml += ` description="${description}"`;
  }
  xml += '>\n';

  // Add properties
  for (const prop of properties) {
    xml += `  <property name="${prop.name}" code="${prop.code}" type="${prop.type}" access="${prop.access}"/>\n`;
  }

  xml += '</class>';
  return xml;
}

/**
 * Assert that a string contains all the specified substrings
 */
export function assertContainsAll(str: string, ...substrings: string[]): void {
  for (const substring of substrings) {
    if (!str.includes(substring)) {
      throw new Error(`Expected string to contain "${substring}", but it didn't`);
    }
  }
}

/**
 * Assert that a string doesn't contain any of the specified substrings
 */
export function assertContainsNone(str: string, ...substrings: string[]): void {
  for (const substring of substrings) {
    if (str.includes(substring)) {
      throw new Error(`Expected string not to contain "${substring}", but it did`);
    }
  }
}

/**
 * Measure execution time of an async function
 */
export async function measureTime<T>(fn: () => Promise<T>): Promise<{ result: T; duration: number }> {
  const start = Date.now();
  const result = await fn();
  const duration = Date.now() - start;
  return { result, duration };
}

/**
 * Run a function multiple times and return average execution time
 */
export async function benchmark<T>(
  fn: () => Promise<T>,
  iterations: number = 10
): Promise<{ averageDuration: number; minDuration: number; maxDuration: number }> {
  const durations: number[] = [];

  for (let i = 0; i < iterations; i++) {
    const { duration } = await measureTime(fn);
    durations.push(duration);
  }

  const averageDuration = durations.reduce((a, b) => a + b, 0) / durations.length;
  const minDuration = Math.min(...durations);
  const maxDuration = Math.max(...durations);

  return { averageDuration, minDuration, maxDuration };
}
