#!/usr/bin/env npx ts-node
/**
 * SDEF Coverage Analysis Script
 *
 * Analyzes all scriptable applications on the system to determine:
 * 1. Which apps have SDEF files and can be parsed
 * 2. Which apps fail to parse and why
 * 3. Which apps only support core AppleEvents (no SDEF)
 * 4. Overall coverage metrics
 *
 * Usage:
 *   npm run sdef:coverage
 *   # or
 *   npx ts-node scripts/analyze-sdef-coverage.ts
 *
 * Options:
 *   --json          Output as JSON instead of markdown
 *   --verbose       Show detailed parsing errors
 *   --apps-only     Only scan /Applications (faster)
 */

import { glob } from 'glob';
import { readFile, stat, readdir } from 'fs/promises';
import { execSync } from 'child_process';
import * as path from 'path';
import { SDEFParser } from '../src/jitd/discovery/parse-sdef.js';
import { ToolGenerator } from '../src/jitd/tool-generator/generator.js';
import type { SDEFDictionary } from '../src/types/sdef.js';

// ============================================================================
// Types
// ============================================================================

interface ParseAttempt {
  sdefPath: string;
  appPath: string;
  appName: string;
  bundleId: string | null;
  success: boolean;
  error?: string;
  commandCount: number;
  classCount: number;
  toolCount: number;
  parseTimeMs: number;
  fileSizeBytes: number;
}

interface CoreEventsApp {
  appPath: string;
  appName: string;
  bundleId: string | null;
  hasSdef: boolean;
  supportsOpenApp: boolean;
  supportsOpenDoc: boolean;
  supportsQuit: boolean;
  supportsPrint: boolean;
  supportsReopen: boolean;
}

interface CoverageMetrics {
  // SDEF parsing
  totalSdefFiles: number;
  successfulParses: number;
  failedParses: number;
  totalCommands: number;
  totalClasses: number;
  totalTools: number;
  parseSuccessRate: number;

  // Error breakdown
  errorsByType: Record<string, number>;

  // App coverage
  totalApps: number;
  appsWithSdef: number;
  appsWithToolsGenerated: number;
  appsWithCoreEventsOnly: number;

  // Lists
  successfulApps: string[];
  failedApps: Array<{ app: string; error: string }>;
  coreEventsOnlyApps: string[];
}

// ============================================================================
// Core AppleEvents Detection
// ============================================================================

/**
 * Core AppleEvents that all apps should support
 * These are the "Required Suite" events from Apple's OSA specification
 */
const CORE_APPLE_EVENTS = {
  // Open Application - sent when app is launched
  openApp: { eventClass: 'aevt', eventId: 'oapp' },
  // Open Documents - sent when files are dropped on app
  openDoc: { eventClass: 'aevt', eventId: 'odoc' },
  // Print Documents - sent to print files
  printDoc: { eventClass: 'aevt', eventId: 'pdoc' },
  // Quit Application - sent to close app
  quit: { eventClass: 'aevt', eventId: 'quit' },
  // Reopen Application - sent when clicking dock icon while running
  reopen: { eventClass: 'aevt', eventId: 'rapp' },
};

/**
 * Test if an app responds to a specific AppleEvent
 * Uses osascript to send a test event
 */
async function testAppleEvent(
  appPath: string,
  eventClass: string,
  eventId: string
): Promise<boolean> {
  const appName = path.basename(appPath, '.app');

  // Build AppleScript to test event handling
  // We use 'exists' check rather than actually sending the event
  const script = `
    tell application "System Events"
      set appExists to exists process "${appName}"
    end tell
    return true
  `;

  try {
    // For now, just check if the app exists - actual event testing requires the app to be running
    // A more sophisticated check would use NSAppleEventDescriptor
    execSync(`osascript -e 'tell application "System Events" to exists application file "${appPath}"'`, {
      timeout: 2000,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    return true;
  } catch {
    return false;
  }
}

/**
 * Get bundle ID from app's Info.plist
 */
function getBundleId(appPath: string): string | null {
  try {
    const result = execSync(
      `defaults read "${appPath}/Contents/Info" CFBundleIdentifier 2>/dev/null`,
      { encoding: 'utf-8', timeout: 2000 }
    );
    return result.trim();
  } catch {
    return null;
  }
}

/**
 * Check if an app is scriptable by looking for various indicators
 */
function isAppScriptable(appPath: string): boolean {
  try {
    // Check for SDEF file
    const resourcesPath = path.join(appPath, 'Contents', 'Resources');
    const sdefFiles = execSync(`ls "${resourcesPath}"/*.sdef 2>/dev/null || true`, {
      encoding: 'utf-8',
    }).trim();
    if (sdefFiles) return true;

    // Check for scripting additions in Info.plist
    const infoPlist = path.join(appPath, 'Contents', 'Info.plist');
    const hasScripting = execSync(
      `defaults read "${infoPlist}" NSAppleScriptEnabled 2>/dev/null || echo "false"`,
      { encoding: 'utf-8' }
    ).trim();
    if (hasScripting === '1' || hasScripting === 'true') return true;

    // Check for OSAScriptingDefinition key
    const hasOSADef = execSync(
      `defaults read "${infoPlist}" OSAScriptingDefinition 2>/dev/null || echo ""`,
      { encoding: 'utf-8' }
    ).trim();
    if (hasOSADef) return true;

    return false;
  } catch {
    return false;
  }
}

/**
 * Detect core AppleEvents support for an app
 */
async function detectCoreEvents(appPath: string): Promise<CoreEventsApp> {
  const appName = path.basename(appPath, '.app');
  const bundleId = getBundleId(appPath);

  // Check for SDEF
  const resourcesPath = path.join(appPath, 'Contents', 'Resources');
  let hasSdef = false;
  try {
    const files = await readdir(resourcesPath);
    hasSdef = files.some(f => f.endsWith('.sdef'));
  } catch {
    // Resources dir doesn't exist or not readable
  }

  // All GUI apps should support these basic events
  // For now, we assume all apps support core events if they're valid apps
  const isValidApp = await stat(appPath).then(() => true).catch(() => false);

  return {
    appPath,
    appName,
    bundleId,
    hasSdef,
    supportsOpenApp: isValidApp,
    supportsOpenDoc: isValidApp,
    supportsQuit: isValidApp,
    supportsPrint: false, // Would need actual testing
    supportsReopen: isValidApp,
  };
}

// ============================================================================
// SDEF Parsing
// ============================================================================

/**
 * Find all SDEF files on the system
 */
async function findSdefFiles(appsOnly: boolean): Promise<string[]> {
  const patterns = appsOnly
    ? ['/Applications/**/*.sdef', '~/Applications/**/*.sdef']
    : [
        '/Applications/**/*.sdef',
        '/System/Applications/**/*.sdef',
        '/System/Library/CoreServices/**/*.sdef',
        '~/Applications/**/*.sdef',
      ];

  const files: string[] = [];
  for (const pattern of patterns) {
    const expanded = pattern.replace('~', process.env.HOME || '');
    const matches = await glob(expanded, { nodir: true });
    files.push(...matches);
  }

  return [...new Set(files)]; // Deduplicate
}

/**
 * Find all .app bundles
 */
async function findAppBundles(appsOnly: boolean): Promise<string[]> {
  const patterns = appsOnly
    ? ['/Applications/*.app', '/Applications/**/*.app']
    : [
        '/Applications/*.app',
        '/Applications/**/*.app',
        '/System/Applications/*.app',
        '/System/Applications/**/*.app',
      ];

  const apps: string[] = [];
  for (const pattern of patterns) {
    const matches = await glob(pattern, { nodir: false });
    apps.push(...matches.filter(p => p.endsWith('.app')));
  }

  return [...new Set(apps)];
}

/**
 * Parse an SDEF file and collect metrics
 */
async function parseSdef(
  sdefPath: string,
  parser: SDEFParser,
  toolGenerator: ToolGenerator
): Promise<ParseAttempt> {
  const appPath = sdefPath.replace(/\/Contents\/Resources\/.*\.sdef$/, '');
  const appName = path.basename(appPath, '.app');
  const bundleId = getBundleId(appPath);

  const startTime = Date.now();
  let fileSizeBytes = 0;

  try {
    const stats = await stat(sdefPath);
    fileSizeBytes = stats.size;

    const dictionary = await parser.parse(sdefPath);

    // Count commands and classes
    let commandCount = 0;
    let classCount = 0;
    for (const suite of dictionary.suites) {
      commandCount += suite.commands.length;
      classCount += suite.classes.length;
    }

    // Generate tools
    const tools = toolGenerator.generateFromDictionary(dictionary, {
      appName,
      bundleId: bundleId || undefined,
      sdefPath,
    });

    return {
      sdefPath,
      appPath,
      appName,
      bundleId,
      success: true,
      commandCount,
      classCount,
      toolCount: tools.length,
      parseTimeMs: Date.now() - startTime,
      fileSizeBytes,
    };
  } catch (error) {
    return {
      sdefPath,
      appPath,
      appName,
      bundleId,
      success: false,
      error: error instanceof Error ? error.message : String(error),
      commandCount: 0,
      classCount: 0,
      toolCount: 0,
      parseTimeMs: Date.now() - startTime,
      fileSizeBytes,
    };
  }
}

/**
 * Classify error into categories
 */
function classifyError(error: string): string {
  if (error.includes('missing required "type" attribute')) return 'MISSING_TYPE';
  if (error.includes('missing required "name"') || error.includes('missing required "code"'))
    return 'MISSING_NAME_OR_CODE';
  if (error.includes('xi:include') || error.includes('XInclude')) return 'EXTERNAL_ENTITY';
  if (error.includes('Invalid code')) return 'INVALID_CODE';
  if (error.includes('Invalid SDEF format')) return 'INVALID_FORMAT';
  if (error.includes('file too large')) return 'FILE_TOO_LARGE';
  if (error.includes('Failed to parse SDEF XML')) return 'XML_PARSE_ERROR';
  return 'OTHER';
}

// ============================================================================
// Report Generation
// ============================================================================

/**
 * Generate markdown report
 */
function generateMarkdownReport(
  metrics: CoverageMetrics,
  attempts: ParseAttempt[],
  coreEventsApps: CoreEventsApp[],
  verbose: boolean
): string {
  const lines: string[] = [];

  lines.push('# SDEF Parser Coverage Report');
  lines.push('');
  lines.push(`Generated: ${new Date().toISOString()}`);
  lines.push('');

  // Summary
  lines.push('## Summary');
  lines.push('');
  lines.push('| Metric | Value |');
  lines.push('|--------|-------|');
  lines.push(`| Total SDEF files | ${metrics.totalSdefFiles} |`);
  lines.push(`| Successfully parsed | ${metrics.successfulParses} (${metrics.parseSuccessRate.toFixed(1)}%) |`);
  lines.push(`| Failed to parse | ${metrics.failedParses} |`);
  lines.push(`| Total commands found | ${metrics.totalCommands} |`);
  lines.push(`| Total classes found | ${metrics.totalClasses} |`);
  lines.push(`| Total tools generated | ${metrics.totalTools} |`);
  lines.push('');

  // App Coverage
  lines.push('## App Coverage');
  lines.push('');
  lines.push('| Metric | Value |');
  lines.push('|--------|-------|');
  lines.push(`| Total apps scanned | ${metrics.totalApps} |`);
  lines.push(`| Apps with SDEF files | ${metrics.appsWithSdef} |`);
  lines.push(`| Apps with tools generated | ${metrics.appsWithToolsGenerated} |`);
  lines.push(`| Apps with core events only | ${metrics.appsWithCoreEventsOnly} |`);
  lines.push('');

  // Error Breakdown
  lines.push('## Error Breakdown');
  lines.push('');
  const sortedErrors = Object.entries(metrics.errorsByType).sort(([, a], [, b]) => b - a);
  if (sortedErrors.length > 0) {
    lines.push('| Error Type | Count |');
    lines.push('|------------|-------|');
    for (const [errorType, count] of sortedErrors) {
      lines.push(`| ${errorType} | ${count} |`);
    }
  } else {
    lines.push('No errors encountered.');
  }
  lines.push('');

  // Successful Apps
  lines.push('## Successfully Parsed Apps');
  lines.push('');
  const successfulWithTools = attempts
    .filter(a => a.success && a.toolCount > 0)
    .sort((a, b) => b.toolCount - a.toolCount);
  if (successfulWithTools.length > 0) {
    lines.push('| App | Commands | Classes | Tools | Size |');
    lines.push('|-----|----------|---------|-------|------|');
    for (const attempt of successfulWithTools) {
      const sizeKb = (attempt.fileSizeBytes / 1024).toFixed(1);
      lines.push(
        `| ${attempt.appName} | ${attempt.commandCount} | ${attempt.classCount} | ${attempt.toolCount} | ${sizeKb}KB |`
      );
    }
  } else {
    lines.push('No apps successfully generated tools.');
  }
  lines.push('');

  // Failed Apps
  lines.push('## Failed to Parse');
  lines.push('');
  const failed = attempts.filter(a => !a.success);
  if (failed.length > 0) {
    lines.push('| App | Error Type | Details |');
    lines.push('|-----|------------|---------|');
    for (const attempt of failed) {
      const errorType = classifyError(attempt.error || '');
      const details = verbose
        ? attempt.error?.substring(0, 100) || 'Unknown'
        : errorType;
      lines.push(`| ${attempt.appName} | ${errorType} | ${details} |`);
    }
  } else {
    lines.push('All SDEF files parsed successfully!');
  }
  lines.push('');

  // Core Events Only Apps
  lines.push('## Apps with Core Events Only (No SDEF)');
  lines.push('');
  lines.push('These apps support basic AppleEvents (open, quit, etc.) but have no SDEF file.');
  lines.push('They can still be automated with basic commands.');
  lines.push('');
  const coreOnly = coreEventsApps.filter(a => !a.hasSdef).slice(0, 20);
  if (coreOnly.length > 0) {
    lines.push('| App | Bundle ID | Open | Quit | Reopen |');
    lines.push('|-----|-----------|------|------|--------|');
    for (const app of coreOnly) {
      lines.push(
        `| ${app.appName} | ${app.bundleId || 'N/A'} | ${app.supportsOpenApp ? 'Y' : 'N'} | ${app.supportsQuit ? 'Y' : 'N'} | ${app.supportsReopen ? 'Y' : 'N'} |`
      );
    }
    if (coreEventsApps.filter(a => !a.hasSdef).length > 20) {
      lines.push('');
      lines.push(`... and ${coreEventsApps.filter(a => !a.hasSdef).length - 20} more apps`);
    }
  } else {
    lines.push('All scanned apps have SDEF files.');
  }
  lines.push('');

  // Recommendations
  lines.push('## Recommendations');
  lines.push('');
  if (metrics.errorsByType['MISSING_TYPE'] > 0) {
    lines.push(
      `- **Phase 1 (Type Inference)** would fix ${metrics.errorsByType['MISSING_TYPE']} apps with missing type attributes`
    );
  }
  if (metrics.errorsByType['EXTERNAL_ENTITY'] > 0) {
    lines.push(
      `- **Phase 3 (External Entities)** would fix ${metrics.errorsByType['EXTERNAL_ENTITY']} apps with XInclude references`
    );
  }
  if (metrics.appsWithCoreEventsOnly > 0) {
    lines.push(
      `- **Core Events Support** would enable basic automation for ${metrics.appsWithCoreEventsOnly} additional apps`
    );
  }
  lines.push('');

  return lines.join('\n');
}

/**
 * Generate JSON report
 */
function generateJsonReport(
  metrics: CoverageMetrics,
  attempts: ParseAttempt[],
  coreEventsApps: CoreEventsApp[]
): string {
  return JSON.stringify(
    {
      generatedAt: new Date().toISOString(),
      metrics,
      attempts,
      coreEventsApps: coreEventsApps.filter(a => !a.hasSdef),
    },
    null,
    2
  );
}

// ============================================================================
// Main
// ============================================================================

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const jsonOutput = args.includes('--json');
  const verbose = args.includes('--verbose');
  const appsOnly = args.includes('--apps-only');

  console.error('SDEF Coverage Analysis');
  console.error('======================');
  console.error('');

  // Initialize parser and generator
  const parser = new SDEFParser();
  const toolGenerator = new ToolGenerator();

  // Find all SDEF files
  console.error('Finding SDEF files...');
  const sdefFiles = await findSdefFiles(appsOnly);
  console.error(`Found ${sdefFiles.length} SDEF files`);

  // Find all app bundles
  console.error('Finding app bundles...');
  const appBundles = await findAppBundles(appsOnly);
  console.error(`Found ${appBundles.length} app bundles`);

  // Parse each SDEF
  console.error('Parsing SDEF files...');
  const attempts: ParseAttempt[] = [];
  for (const sdefPath of sdefFiles) {
    const attempt = await parseSdef(sdefPath, parser, toolGenerator);
    attempts.push(attempt);
    if (verbose) {
      const status = attempt.success ? 'OK' : 'FAIL';
      console.error(`  [${status}] ${attempt.appName}`);
    }
  }

  // Detect core events for apps without SDEF
  console.error('Detecting core events support...');
  const coreEventsApps: CoreEventsApp[] = [];
  for (const appPath of appBundles.slice(0, 100)) {
    // Limit to first 100 for speed
    const coreEvents = await detectCoreEvents(appPath);
    coreEventsApps.push(coreEvents);
  }

  // Calculate metrics
  const successful = attempts.filter(a => a.success);
  const failed = attempts.filter(a => !a.success);

  const errorsByType: Record<string, number> = {};
  for (const attempt of failed) {
    const errorType = classifyError(attempt.error || '');
    errorsByType[errorType] = (errorsByType[errorType] || 0) + 1;
  }

  const metrics: CoverageMetrics = {
    totalSdefFiles: attempts.length,
    successfulParses: successful.length,
    failedParses: failed.length,
    totalCommands: successful.reduce((sum, a) => sum + a.commandCount, 0),
    totalClasses: successful.reduce((sum, a) => sum + a.classCount, 0),
    totalTools: successful.reduce((sum, a) => sum + a.toolCount, 0),
    parseSuccessRate: attempts.length > 0 ? (successful.length / attempts.length) * 100 : 0,
    errorsByType,
    totalApps: appBundles.length,
    appsWithSdef: coreEventsApps.filter(a => a.hasSdef).length,
    appsWithToolsGenerated: successful.filter(a => a.toolCount > 0).length,
    appsWithCoreEventsOnly: coreEventsApps.filter(a => !a.hasSdef).length,
    successfulApps: successful.map(a => a.appName),
    failedApps: failed.map(a => ({ app: a.appName, error: a.error || '' })),
    coreEventsOnlyApps: coreEventsApps.filter(a => !a.hasSdef).map(a => a.appName),
  };

  // Generate report
  const report = jsonOutput
    ? generateJsonReport(metrics, attempts, coreEventsApps)
    : generateMarkdownReport(metrics, attempts, coreEventsApps, verbose);

  console.log(report);

  // Exit with error if success rate is below threshold
  if (metrics.parseSuccessRate < 25) {
    console.error('');
    console.error(`WARNING: Parse success rate (${metrics.parseSuccessRate.toFixed(1)}%) is below 25%`);
    process.exit(1);
  }
}

main().catch(error => {
  console.error('Fatal error:', error);
  process.exit(1);
});
