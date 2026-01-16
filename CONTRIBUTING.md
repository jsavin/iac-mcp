# Contributing to iac-mcp

Thank you for your interest in contributing! This project is in **Phase 0 (Technical Validation)** and not yet accepting external contributions.

## Current Status

We're currently proving the JITD (Just-In-Time Discovery) concept works on macOS. Once Phase 0 is complete and the core architecture is validated, we'll open up for contributions.

## Future Contribution Areas

When we're ready for contributions (Phase 1+), we'll be looking for help with:

- **Platform adapters**: Windows (VBA/COM), Linux (D-Bus)
- **Additional app integrations**: Testing with different scriptable apps
- **Documentation**: Guides, examples, tutorials
- **Testing**: Unit tests, integration tests, edge cases
- **Bug fixes**: Issues reported by the community

## Development Setup

If you're interested in exploring the codebase:

1. **Prerequisites**:
   - macOS Monterey or later (for Phase 1)
   - Node.js 20.11+ (use nvm or volta)
   - Claude Desktop (for testing)

2. **Setup**:
   ```bash
   git clone https://github.com/jsavin/iac-mcp.git
   cd iac-mcp
   nvm use  # or volta will auto-detect
   npm ci   # install exact dependency versions
   npm run build
   npm run verify
   ```

3. **Read the docs**:
   - [CLAUDE.md](CLAUDE.md) - Development workflow and patterns
   - [planning/START-HERE.md](planning/START-HERE.md) - Project overview
   - [planning/VISION.md](planning/VISION.md) - Strategic vision
   - [planning/ROADMAP.md](planning/ROADMAP.md) - 18-month plan

## Code of Conduct

This project adheres to a Code of Conduct that all contributors are expected to follow. We're committed to providing a welcoming and inclusive environment.

## Questions?

- **Technical questions**: Open a discussion (when enabled)
- **Strategic questions**: See planning docs
- **Bug reports**: Will accept once Phase 0 is complete

## Stay Updated

Watch this repository to get notified when we open up for contributions!

---

**Status**: Not yet accepting contributions (Phase 0)
**Next milestone**: JITD proof of concept → Open for contributions in Phase 1
