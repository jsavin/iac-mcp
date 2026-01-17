# Quick Start Guide: Claude Desktop Integration

Get iac-mcp running with Claude Desktop in 5 minutes.

## Prerequisites

- macOS Monterey or later
- Node.js 20+
- Claude Desktop installed

## Step 1: Build the Server

```bash
cd /path/to/iac-mcp
npm ci
npm run build
```

## Step 2: Get Your Absolute Path

```bash
pwd
# Example output: /Users/yourusername/dev/iac-mcp
# Copy this path
```

## Step 3: Configure Claude Desktop

1. Open (or create) the Claude Desktop config file:
   ```bash
   open ~/Library/Application\ Support/Claude/claude_desktop_config.json
   ```

2. Add this configuration (replace the path with yours from Step 2):
   ```json
   {
     "mcpServers": {
       "iac-mcp": {
         "command": "node",
         "args": ["/your/absolute/path/iac-mcp/dist/index.js"],
         "env": {
           "NODE_ENV": "production"
         }
       }
     }
   }
   ```

3. Save the file

## Step 4: Restart Claude Desktop

1. Quit Claude Desktop completely (Cmd+Q)
2. Relaunch Claude Desktop

## Step 5: Test It

Open a new conversation in Claude Desktop and try:

```
Use the example_tool to echo "Hello from iac-mcp!"
```

You should see:
```
Echo: Hello from iac-mcp!
```

## Troubleshooting

### Server not appearing?

1. Check the absolute path in your config is correct
2. Verify the project built successfully: `ls dist/index.js`
3. Check Node.js version: `node --version` (must be 20+)
4. Try restarting Claude Desktop again

### Want to see server logs?

Run the server manually in a terminal:
```bash
node dist/index.js
```

Then use Claude Desktop. Logs will appear in the terminal.

### Test with MCP Inspector first

Before configuring Claude Desktop, test with MCP Inspector:
```bash
npx @modelcontextprotocol/inspector node dist/index.js
```

This opens a browser where you can test the server independently.

## Next Steps

- Read [MANUAL-TESTING.md](MANUAL-TESTING.md) for comprehensive testing
- Check [README.md](../README.md) for full documentation
- Review [.github/SETUP.md](../.github/SETUP.md) for development setup

## Need Help?

- Check [MANUAL-TESTING.md](MANUAL-TESTING.md) - Common Issues section
- Review [README.md](../README.md) - Troubleshooting section
- Verify your setup matches [.github/SETUP.md](../.github/SETUP.md)

---

**Pro Tip:** Use the MCP Inspector to test and debug before connecting to Claude Desktop. It's much easier to troubleshoot issues in the browser interface.
