#!/usr/bin/env node
/**
 * Clear JITD cache before build
 *
 * Removes cached SDEF data and generated tools to ensure fresh discovery
 * after code changes. This prevents stale data from being served to clients.
 */

import { rmSync } from 'fs';
import { join } from 'path';
import { homedir, tmpdir } from 'os';

const cacheLocations = [
  // Per-app cache (current implementation)
  join(homedir(), '.cache', 'iac-mcp'),
  // Tool cache (legacy location)
  join(tmpdir(), 'iac-mcp-cache'),
];

console.log('[Cache Clear] Clearing JITD cache before build...');

for (const cacheDir of cacheLocations) {
  try {
    rmSync(cacheDir, { recursive: true, force: true });
    console.log(`[Cache Clear] ✓ Removed: ${cacheDir}`);
  } catch (error) {
    // Silently ignore errors (directory might not exist)
  }
}

console.log('[Cache Clear] Cache cleared successfully');
