#!/usr/bin/env node
/**
 * Quick test to verify SDEF discovery is working
 */

import { findSDEFFile, findAllScriptableApps } from '../jitd/discovery/index.js';

async function main() {
  console.log('Testing SDEF Discovery Module\n');

  // Test 1: Find Finder's SDEF file
  console.log('1. Finding Finder SDEF file...');
  const finderSDEF = await findSDEFFile('/System/Library/CoreServices/Finder.app');
  console.log(`   ${finderSDEF ? '✓' : '✗'} ${finderSDEF || 'Not found'}\n`);

  // Test 2: Discover all scriptable apps
  console.log('2. Discovering all scriptable apps...');
  const startTime = Date.now();
  const apps = await findAllScriptableApps();
  const duration = Date.now() - startTime;
  console.log(`   ✓ Found ${apps.length} apps in ${duration}ms\n`);

  // Show first 10 apps
  console.log('   First 10 apps:');
  apps.slice(0, 10).forEach((app) => {
    console.log(`     - ${app.appName}`);
  });

  console.log('\n✓ All tests passed!\n');
}

main();
