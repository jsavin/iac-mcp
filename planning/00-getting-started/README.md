# Planning Documents

This directory contains planning and design documents for the IAC MCP Bridge project.

## Start Here

📘 **[VISION.md](VISION.md)** - Read this first for the complete vision overview

## The Vision

This project builds a **universal bridge layer** connecting AI/LLMs to native applications, enabling AI-powered automation across the rich ecosystem of native apps everyone else ignores.

**Core philosophy:** Interoperability above all. Make everything work with everything else.

**Key insight:** AI companies are web-centric and miss the vast world of native apps (creative tools, productivity apps, specialized software). This bridges that gap with Just-In-Time Discovery (JITD) of any installed app's capabilities.

## Document Structure

### Vision & Philosophy
- **[VISION.md](VISION.md)** - Executive summary and overview (start here)
- **[ideas/](ideas/)** - Detailed vision documents, concepts, and strategic thinking

### Technical Planning (Early Drafts)
- **[technical/](technical/)** - Implementation details (discovery, permissions, MCP interface)
- **[architecture/](architecture/)** - Architectural decisions (distribution model)

### Business
- **[business/](business/)** - Business model and monetization (placeholder)

## Key Ideas Documents

Located in `ideas/` directory:

1. **[the-complete-vision.md](ideas/the-complete-vision.md)** - The complete picture: two complementary projects (this bridge + modernized Frontier), market gap, strategy
2. **[frontier-vision.md](ideas/frontier-vision.md)** - Frontier legacy, democratizing AI automation, product vision
3. **[product-reframe.md](ideas/product-reframe.md)** - Evolution from "MCP server" to "complete product"
4. **[jitd-concept.md](ideas/jitd-concept.md)** - Just-In-Time Discovery: the core technical insight
5. **[universal-iac-vision.md](ideas/universal-iac-vision.md)** - Cross-platform IAC architecture
6. **[tool-explosion-solutions.md](ideas/tool-explosion-solutions.md)** - Handling 10,000+ potential tools
7. **[architecture-overview.md](ideas/architecture-overview.md)** - System design and components

## Status

🔵 **Vision Phase** - Core vision documented, ready to discuss implementation strategy

## Critical Decisions Needed

1. **Build order:** Phase 1 (MCP bridge for developers) or Phase 2 (native app for users) first?
2. **Frontier integration:** Design for it now or prove concept independently first?
3. **Technology stack:** If building native app, Electron vs Swift?
4. **Business model:** Free for developers? Paid native app? Freemium?
5. **Project name:** Keep `osa-mcp` or choose product-focused name?

## Next Steps

- [ ] Align on build order (MCP bridge vs native app first)
- [ ] Prototype JITD proof of concept (Finder SDEF → tools → execution)
- [ ] Validate technical assumptions (MCP tool limits, LLM behavior)
- [ ] Choose technology stack for Phase 1
- [ ] Design Frontier integration points
- [ ] Define MVP scope
- [ ] Create development roadmap
