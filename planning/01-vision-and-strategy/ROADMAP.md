# Technical Development Roadmap

## Overview

**Goal:** Build a universal bridge between AI/LLMs and native Mac applications
**Strategy:** Open source MCP bridge + native UI
**Timeline:** Phased development approach
**Availability:** Part-time development (20-30 hours/week)

## Phase 0: Technical Validation (Weeks 1-4)

**Goal:** Prove JITD (Just-In-Time Discovery) concept works

### Week 1-2: SDEF Parsing Prototype
- [ ] Parse Finder.app SDEF file
- [ ] Extract commands, parameters, classes
- [ ] Convert to structured format (JSON)
- [ ] Document findings and challenges

**Deliverable:** Working SDEF parser for one app

### Week 3-4: Tool Generation Prototype
- [ ] Generate MCP tool definitions from parsed SDEF
- [ ] Create JSON schemas for parameters
- [ ] Test with Claude Desktop manually
- [ ] Execute simple Finder command via JXA

**Deliverable:** Proof that "SDEF → Tools → Execution" works

**Validation criteria:**
- ✅ Can parse SDEF successfully
- ✅ Can generate valid MCP tool schema
- ✅ Claude Desktop can call generated tool
- ✅ Tool execution actually works

**Decision point:** If this fails, reconsider approach. If succeeds, proceed to Phase 1.

---

## Phase 1: MCP Bridge Core (Months 2-5)

**Goal:** Working MCP server that supports 10-15 apps
**Timeline:** ~16 weeks

### Month 2: Core Engine (Weeks 5-8)
- [ ] JITD engine (discovery, caching, tool generation)
- [ ] Application scanner (find .app bundles with SDEF files)
- [ ] SDEF parser (robust, handles variants)
- [ ] Tool generator (SDEF → MCP tool definitions)
- [ ] Cache system (avoid re-parsing on every startup)

**Target apps:** Finder, Safari, Mail, Calendar, Notes

### Month 3: Execution Layer (Weeks 9-12)
- [ ] macOS adapter (AppleEvents via JXA)
- [ ] Parameter marshaling (JSON → AppleScript types)
- [ ] Result parsing (AppleScript output → JSON)
- [ ] Error handling (graceful failures)
- [ ] Timeout management

**Test:** Can execute commands on all 5 target apps

### Month 4: MCP Integration (Weeks 13-16)
- [ ] MCP server implementation (stdio transport)
- [ ] ListTools handler (return all discovered tools)
- [ ] CallTool handler (execute tool, return result)
- [ ] ListResources handler (expose app dictionaries)
- [ ] ReadResource handler (return capability details)

**Test:** Works with Claude Desktop end-to-end

### Month 5: Polish & Expand (Weeks 17-20)
- [ ] Basic permission system (allow/deny/always allow)
- [ ] Audit log (track what was executed)
- [ ] Expand to 10-15 apps (Messages, Photos, Music, Reminders, TextEdit, Preview, Contacts, Podcasts, TV, Books)
- [ ] Documentation (README, usage guide)
- [ ] Unit tests for core functionality

**Deliverable:** Open source MCP bridge on GitHub/npm

---

## Phase 2: Native UI (Months 6-9)

**Goal:** Native macOS app with basic workflow management
**Timeline:** ~16 weeks

### Month 6: Swift App Foundation (Weeks 21-24)
- [ ] Xcode project setup
- [ ] Menu bar app or main window app (decide which)
- [ ] Swift → Node.js IPC design (choose approach)
- [ ] Spawn Node.js MCP bridge from Swift
- [ ] Basic communication (Swift can call bridge)

**Test:** Swift app can start backend and query available tools

### Month 7: Core UI (Weeks 25-28)
- [ ] App discovery panel (show discovered apps)
- [ ] Workflow list (saved workflows)
- [ ] Workflow editor (simple form-based, not visual canvas yet)
- [ ] Run workflow (trigger execution, show results)
- [ ] Settings (enable/disable apps, configuration)

**Test:** Can create, save, and run workflows from UI

### Month 8: Permission System UI (Weeks 29-32)
- [ ] Native permission dialogs (NSAlert or custom)
- [ ] "Always allow" checkbox
- [ ] Permission management (view/revoke permissions)
- [ ] Audit log viewer (what ran when)

**Test:** Safe to use, users feel in control

### Month 9: Polish & Prepare for Beta (Weeks 33-36)
- [ ] Onboarding flow (first-time user experience)
- [ ] Error handling and user-friendly messages
- [ ] Help/documentation (in-app)
- [ ] Icon and branding
- [ ] App signing and notarization

**Deliverable:** Beta-ready native macOS app

---

## Phase 3: Launch & Initial Release (Months 10-12)

**Goal:** Public release and validation
**Timeline:** ~12 weeks

### Month 10: Public Launch (Weeks 37-40)
- [ ] Landing page and documentation
- [ ] Package distribution (Homebrew, npm, direct download)
- [ ] Open source announcement (HN, Reddit, Twitter)
- [ ] Community building (Discord, GitHub Discussions)

### Month 11: Community Feedback (Weeks 41-44)
- [ ] Content creation (blog posts, use cases, tutorials)
- [ ] Video demonstrations
- [ ] Outreach to Mac productivity communities
- [ ] Support infrastructure
- [ ] Bug fixes based on feedback

### Month 12: Iterate & Stabilize (Weeks 45-48)
- [ ] Feature improvements based on feedback
- [ ] Better onboarding (reduce friction)
- [ ] Performance optimization
- [ ] Additional app support (based on requests)
- [ ] Community workflow sharing

**Deliverable:** Stable 1.0 release

---

## Phase 4: Advanced Features (Months 13-18)

**Goal:** Enhanced capabilities and user experience
**Timeline:** ~24 weeks

### Months 13-15: Product Improvements
- [ ] Conversational workflow builder (AI assistant chat)
- [ ] Workflow sharing (import/export)
- [ ] Community workflows (library)
- [ ] Scheduled workflows (run at specific times)
- [ ] Mac App Store submission (broader reach)

### Months 16-18: Platform Growth
- [ ] Content and tutorials (blog posts for each app)
- [ ] Video tutorials (specific workflows)
- [ ] Community partnerships
- [ ] User testimonials and case studies
- [ ] Developer API documentation

**Deliverable:** Feature-complete 2.0 release

---

## Phase 5: Platform Expansion (Months 19-24+)

**Goal:** Multi-platform and advanced automation
**Timeline:** Ongoing

### Accessibility API Support (Tier 2)
- Support non-scriptable apps via macOS Accessibility APIs
- Expand coverage from 30-40% to 60-70% of apps
- Advanced automation capabilities

### Cross-Platform Support
- Port discovery layer (Windows COM introspection, Linux D-Bus)
- Windows platform adapter (PowerShell, COM execution)
- Linux platform adapter (D-Bus, CLI tools)
- Cross-platform UI considerations

### Vision AI Support (Tier 3)
- Screenshot + vision AI for any visible app
- GUI automation capabilities
- Near-universal coverage (95%+ of apps)

### Advanced Features
- Team sharing and collaboration
- Workflow templates and marketplace
- Integration with other automation tools
- API for third-party extensions

---

## Key Technical Milestones

| Milestone | Timeline | Success Criteria |
|-----------|----------|------------------|
| Technical validation | Month 1 | JITD proof of concept works with 1 app |
| Open source core | Month 5 | MCP bridge released, community interest |
| Beta launch | Month 9 | Native app functional, beta testers using it |
| Public release | Month 10 | 1.0 release, stable and documented |
| Feature complete | Month 18 | 2.0 release with advanced features |
| Multi-platform | Month 24+ | Cross-platform support |

---

## Risk Mitigation

### Technical Risks
- **JITD doesn't work:** Prototype early (Phase 0 validates)
- **Hybrid architecture too complex:** Have Electron fallback plan
- **Apps don't work reliably:** Focus on most popular apps first

### Adoption Risks
- **Developers don't adopt:** Ensure excellent documentation and examples
- **Too complex:** Focus on usability and onboarding
- **Performance issues:** Optimize discovery and caching early

### Execution Risks
- **Timeline slips:** Adjust scope, not timeline (ship smaller but on time)
- **Burnout:** Part-time sustainable, can slow down if needed
- **Complexity:** Break into smaller milestones, ship incrementally

---

## Success Criteria by Phase

### Phase 0 Success
- ✅ SDEF parsing works
- ✅ Tool generation works
- ✅ Claude can call tools
- ✅ Execution works

### Phase 1 Success
- ✅ MCP bridge works with 10-15 apps
- ✅ Claude Desktop users can use it
- ✅ Community interest (GitHub stars, issues, PRs)
- ✅ Developer adoption

### Phase 2 Success
- ✅ Native macOS app works well
- ✅ Beta testers providing feedback
- ✅ Positive response from users
- ✅ No critical bugs

### Phase 3 Success
- ✅ Stable 1.0 release
- ✅ Active community
- ✅ Good documentation
- ✅ Positive reviews

### Phase 4 Success
- ✅ Feature-complete 2.0 release
- ✅ Growing community
- ✅ Community-contributed workflows
- ✅ Strong adoption

---

## Next Immediate Actions

### This Week
1. Set up development environment
2. Clone sample .app bundle with SDEF
3. Research SDEF XML structure
4. Build basic XML parser

### Next 2 Weeks
1. Complete SDEF parsing prototype
2. Generate first MCP tool definition
3. Test with Claude Desktop manually
4. Validate technical approach

### Month 1 Goal
Complete Phase 0 and make go/no-go decision on full buildout.

---

**Status:** Phase 0 (Technical Validation)
**Current Focus:** Proving JITD concept with Finder.app
