#!/usr/bin/env node

/**
 * CLI Interface for IAC-MCP
 *
 * Provides command-line interface for:
 * - Starting the MCP server
 * - Discovering installed applications
 * - Testing tool generation
 * - Displaying version and help information
 */

import { existsSync, readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { spawn } from 'child_process';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

interface CliConfig {
  command: string;
  verbose: boolean;
  logLevel?: string;
  cacheDir?: string;
  timeout?: number;
  appName?: string;
}

/**
 * Parse command line arguments
 */
function parseArgs(args: string[]): CliConfig {
  const config: CliConfig = {
    command: 'start',
    verbose: false,
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    if (arg === '--help' || arg === '-h') {
      config.command = 'help';
    } else if (arg === '--version' || arg === '-v') {
      config.command = 'version';
    } else if (arg === '--verbose') {
      config.verbose = true;
    } else if (arg === '--log-level' && i + 1 < args.length) {
      const nextArg = args[++i];
      if (nextArg !== undefined) config.logLevel = nextArg;
    } else if (arg === '--cache-dir' && i + 1 < args.length) {
      const nextArg = args[++i];
      if (nextArg !== undefined) config.cacheDir = nextArg;
    } else if (arg === '--timeout' && i + 1 < args.length) {
      const nextArg = args[++i];
      if (nextArg !== undefined) config.timeout = parseInt(nextArg, 10);
    } else if (arg && !arg.startsWith('-')) {
      // First non-flag argument is the command
      if (!config.command || config.command === 'start') {
        config.command = arg;
      } else {
        // Second non-flag argument is the app name (for 'test' command)
        config.appName = arg;
      }
    }
  }

  return config;
}

/**
 * Get package version
 */
function getVersion(): string {
  try {
    const packagePath = join(__dirname, '../package.json');
    if (existsSync(packagePath)) {
      const pkg = JSON.parse(readFileSync(packagePath, 'utf-8'));
      return pkg.version || '0.0.0';
    }
  } catch (error) {
    // Ignore errors, return default
  }
  return '0.0.0';
}

/**
 * Display help message
 */
function showHelp(): void {
  const version = getVersion();
  console.log(`
IAC-MCP v${version}
Universal bridge between AI/LLMs and native applications using Just-In-Time Discovery

USAGE:
  iac-mcp [command] [options]

COMMANDS:
  start              Start the MCP server (default)
  discover-apps      Discover and list installed scriptable applications
  test <app-name>    Test tool generation with a specific app
  version           Show version information
  help              Show this help message

OPTIONS:
  --verbose         Enable verbose logging
  --log-level <level>   Set log level (error|warn|info|debug)
  --cache-dir <path>    Set cache directory (default: ~/.iac-mcp/cache)
  --timeout <ms>    Set execution timeout in milliseconds (default: 30000)
  -h, --help        Show help
  -v, --version     Show version

EXAMPLES:
  # Start the MCP server
  iac-mcp start

  # Discover installed apps with verbose output
  iac-mcp discover-apps --verbose

  # Test tool generation for a specific app
  iac-mcp test Finder

  # Start server with custom cache directory
  iac-mcp start --cache-dir /tmp/iac-cache

ENVIRONMENT VARIABLES:
  IAC_MCP_LOG_LEVEL     Set log level (error|warn|info|debug)
  IAC_MCP_CACHE_DIR     Set cache directory
  IAC_MCP_TIMEOUT       Set execution timeout in milliseconds

For more information, visit: https://github.com/jsavin/iac-mcp
`);
}

/**
 * Display version information
 */
function showVersion(): void {
  const version = getVersion();
  console.log(`IAC-MCP v${version}`);
  console.log(`Node.js ${process.version}`);
  console.log(`Platform: ${process.platform}`);
}

/**
 * Discover and list installed applications
 */
async function discoverApps(config: CliConfig): Promise<void> {
  console.log('Discovering installed scriptable applications...\n');
  console.log('Note: This functionality will be available in a future update.');
  console.log('For now, please use the MCP server with Claude Desktop.\n');

  if (config.verbose) {
    console.log('Verbose mode enabled');
    console.log('Expected behavior:');
    console.log('  - Scan /Applications for .sdef files');
    console.log('  - Scan /System/Library/CoreServices for system apps');
    console.log('  - Display found apps with bundle IDs and paths\n');
  }
}

/**
 * Test tool generation for a specific app
 */
async function testToolGeneration(appName: string | undefined, config: CliConfig): Promise<void> {
  if (!appName) {
    console.error('Error: Application name required');
    console.error('Usage: iac-mcp test <app-name>');
    process.exit(1);
  }

  console.log(`Testing tool generation for ${appName}...\n`);
  console.log('Note: This functionality will be available in a future update.');
  console.log('For now, please use the MCP server with Claude Desktop.\n');

  if (config.verbose) {
    console.log('Verbose mode enabled');
    console.log('Expected behavior:');
    console.log(`  - Find ${appName}.app and its SDEF file`);
    console.log(`  - Parse SDEF and extract commands`);
    console.log(`  - Generate MCP tool definitions`);
    console.log(`  - Display sample tools\n`);
  }
}

/**
 * Start the MCP server
 */
async function startMcpServer(config: CliConfig): Promise<void> {
  if (config.verbose) {
    console.error('Starting IAC-MCP server...');
    console.error(`  Log level: ${config.logLevel || process.env.IAC_MCP_LOG_LEVEL || 'info'}`);
    console.error(`  Cache dir: ${config.cacheDir || process.env.IAC_MCP_CACHE_DIR || '~/.iac-mcp/cache'}`);
    console.error(`  Timeout: ${config.timeout || process.env.IAC_MCP_TIMEOUT || 30000}ms\n`);
  }

  // Launch the actual server (index.js)
  const serverPath = join(__dirname, 'index.js');

  if (!existsSync(serverPath)) {
    console.error('Error: Server file not found. Please run `npm run build` first.');
    process.exit(1);
  }

  // Pass through to the actual server
  const server = spawn('node', [serverPath], {
    stdio: 'inherit',
    env: {
      ...process.env,
      IAC_MCP_LOG_LEVEL: config.logLevel || process.env.IAC_MCP_LOG_LEVEL,
      IAC_MCP_CACHE_DIR: config.cacheDir || process.env.IAC_MCP_CACHE_DIR,
      IAC_MCP_TIMEOUT: config.timeout ? config.timeout.toString() : process.env.IAC_MCP_TIMEOUT,
    },
  });

  server.on('error', (error) => {
    console.error('Failed to start server:', error);
    process.exit(1);
  });

  server.on('exit', (code) => {
    process.exit(code || 0);
  });
}

/**
 * Main CLI entry point
 */
async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const config = parseArgs(args);

  // Apply environment variables
  if (!config.logLevel && process.env.IAC_MCP_LOG_LEVEL) {
    config.logLevel = process.env.IAC_MCP_LOG_LEVEL;
  }
  if (!config.cacheDir && process.env.IAC_MCP_CACHE_DIR) {
    config.cacheDir = process.env.IAC_MCP_CACHE_DIR;
  }
  if (!config.timeout && process.env.IAC_MCP_TIMEOUT) {
    config.timeout = parseInt(process.env.IAC_MCP_TIMEOUT, 10);
  }

  try {
    switch (config.command) {
      case 'help':
        showHelp();
        break;

      case 'version':
        showVersion();
        break;

      case 'discover-apps':
        await discoverApps(config);
        break;

      case 'test':
        await testToolGeneration(config.appName, config);
        break;

      case 'start':
      default:
        await startMcpServer(config);
        break;
    }
  } catch (error) {
    console.error('Error:', error);
    process.exit(1);
  }
}

// Run CLI if this is the main module
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(error => {
    console.error('Fatal error:', error);
    process.exit(1);
  });
}

export { main, parseArgs };
