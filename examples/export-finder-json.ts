#!/usr/bin/env tsx

/**
 * Export Finder.sdef to JSON
 *
 * Week 1 deliverable: JSON file with Finder's parsed capabilities
 */

import { sdefParser } from '../src/jitd/discovery/parse-sdef.js';
import { writeFile } from 'fs/promises';
import { join } from 'path';

async function main() {
  const finderSDEF = '/System/Library/CoreServices/Finder.app/Contents/Resources/Finder.sdef';
  const outputPath = join(process.cwd(), 'finder-capabilities.json');

  console.log('Parsing Finder.sdef...');
  const startTime = Date.now();

  const dictionary = await sdefParser.parse(finderSDEF);
  const parseTime = Date.now() - startTime;

  console.log(`✓ Parsed in ${parseTime}ms`);
  console.log(`  Suites: ${dictionary.suites.length}`);
  console.log(`  Commands: ${dictionary.suites.reduce((sum, s) => sum + s.commands.length, 0)}`);
  console.log(`  Classes: ${dictionary.suites.reduce((sum, s) => sum + s.classes.length, 0)}`);
  console.log(`  Enumerations: ${dictionary.suites.reduce((sum, s) => sum + s.enumerations.length, 0)}`);

  console.log(`\nWriting to ${outputPath}...`);
  await writeFile(outputPath, JSON.stringify(dictionary, null, 2), 'utf-8');

  const stats = await import('fs').then(fs => fs.promises.stat(outputPath));
  console.log(`✓ Written ${(stats.size / 1024).toFixed(1)} KB`);
  console.log('\nWeek 1 deliverable complete! ✓');
}

main().catch(console.error);
