#!/usr/bin/env node
/**
 * Manual test script for SDEF discovery
 *
 * This script tests the SDEF discovery functionality with real macOS applications.
 * Run with: npm run build && node dist/tools/test-discovery.js
 */

import {
  findSDEFFile,
  findAllScriptableApps,
  getKnownScriptableApps,
  getSDEFPath,
} from '../jitd/discovery/index.js';

async function testFindSDEFFile() {
  console.log('\n=== Testing findSDEFFile ===\n');

  const testApps = [
    '/System/Library/CoreServices/Finder.app',
    '/System/Applications/Safari.app',
    '/System/Applications/Mail.app',
    '/Applications/ThisAppDoesNotExist.app',
  ];

  for (const appPath of testApps) {
    console.log(`Testing: ${appPath}`);
    try {
      const sdefPath = await findSDEFFile(appPath);
      if (sdefPath) {
        console.log(`  ✓ Found SDEF: ${sdefPath}`);
      } else {
        console.log(`  ✗ No SDEF file found`);
      }
    } catch (error) {
      console.log(`  ✗ Error: ${error}`);
    }
    console.log();
  }
}

async function testGetSDEFPath() {
  console.log('\n=== Testing getSDEFPath ===\n');

  const testApps = [
    '/Applications/Safari.app',
    '/System/Library/CoreServices/Finder.app',
  ];

  for (const appPath of testApps) {
    const expectedPath = getSDEFPath(appPath);
    console.log(`App: ${appPath}`);
    console.log(`Expected SDEF: ${expectedPath}`);
    console.log();
  }
}

async function testFindAllScriptableApps() {
  console.log('\n=== Testing findAllScriptableApps ===\n');

  console.log('Discovering all scriptable apps (this may take a moment)...\n');

  const startTime = Date.now();
  const apps = await findAllScriptableApps();
  const duration = Date.now() - startTime;

  console.log(`Found ${apps.length} scriptable apps in ${duration}ms:\n`);

  // Group by directory
  const byDirectory = new Map<string, typeof apps>();

  for (const app of apps) {
    const dir = app.bundlePath.split('/').slice(0, -1).join('/');
    if (!byDirectory.has(dir)) {
      byDirectory.set(dir, []);
    }
    byDirectory.get(dir)?.push(app);
  }

  // Print grouped results
  for (const [dir, dirApps] of byDirectory.entries()) {
    console.log(`\n${dir}:`);
    for (const app of dirApps) {
      console.log(`  - ${app.appName}`);
    }
  }

  console.log(`\n\nTotal: ${apps.length} scriptable apps`);
}

async function testKnownScriptableApps() {
  console.log('\n=== Testing Known Scriptable Apps ===\n');

  const knownApps = getKnownScriptableApps();
  console.log(`Testing ${knownApps.length} known scriptable apps:\n`);

  for (const appPath of knownApps) {
    const sdefPath = await findSDEFFile(appPath);
    const status = sdefPath ? '✓' : '✗';
    console.log(`${status} ${appPath}`);
  }
}

async function main() {
  console.log('SDEF Discovery Test Suite');
  console.log('=========================');

  try {
    await testGetSDEFPath();
    await testFindSDEFFile();
    await testKnownScriptableApps();
    await testFindAllScriptableApps();

    console.log('\n\n=== All tests completed ===\n');
  } catch (error) {
    console.error('Error running tests:', error);
    process.exit(1);
  }
}

main();
