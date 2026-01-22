import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

// Start server and get its output
const { IACMCPServer } = await import('./dist/index.js');
const server = new IACMCPServer({ cacheDir: '/tmp/iac-cache', enableCache: false });

try {
  await server.initialize();
  const tools = await server.listTools();
  
  console.log(`Total tools: ${tools.tools.length}`);
  
  const appMap = {};
  tools.tools.forEach(tool => {
    const parts = tool.name.split('_');
    const appName = parts[0];
    appMap[appName] = (appMap[appName] || 0) + 1;
  });
  
  console.log('\nTools by app:');
  Object.entries(appMap).sort().forEach(([app, count]) => {
    console.log(`  ${app}: ${count}`);
  });
} catch (err) {
  console.error('Error:', err.message);
}
