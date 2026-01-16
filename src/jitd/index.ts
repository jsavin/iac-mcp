/**
 * JITD (Just-In-Time Discovery) Engine
 *
 * The JITD engine dynamically discovers and orchestrates installed applications
 * without requiring pre-built integrations.
 *
 * Current modules:
 * - discovery: Find SDEF files in macOS application bundles
 *
 * Future modules:
 * - parser: Parse SDEF XML into structured data
 * - tool-generator: Convert SDEF capabilities into MCP tools
 * - cache: Cache parsed capabilities for performance
 */

export * from './discovery/index.js';
