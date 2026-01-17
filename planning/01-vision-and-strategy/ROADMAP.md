# Development Roadmap

## Overview

**Goal:** Build sustainable, profitable bridge between AI and native Mac apps
**Strategy:** Bootstrap with open source core + proprietary UI
**Timeline:** 12-18 months to profitability (growth targets)
**Availability:** 20-30 hours/week (part-time)

## Phase 0: Technical Validation (Weeks 1-4)

**Goal:** Prove JITD concept works

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
**Timeline:** ~16 weeks (4 months @ 20-25 hrs/week)

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

## Phase 2: UI Wrapper (Months 6-9)

**Goal:** Native macOS app with basic workflow management
**Timeline:** ~16 weeks (4 months @ 20-25 hrs/week)

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
- [ ] Settings (enable/disable apps, API keys if needed)

**Test:** Can create, save, and run workflows from UI

### Month 8: Permission System UI (Weeks 29-32)
- [ ] Native permission dialogs (NSAlert or custom)
- [ ] "Always allow" checkbox
- [ ] Permission management (view/revoke permissions)
- [ ] Audit log viewer (what ran when)

**Test:** Safe to use, users feel in control

### Month 9: Polish & Prepare Launch (Weeks 33-36)
- [ ] Onboarding flow (first-time user experience)
- [ ] Error handling and user-friendly messages
- [ ] Help/documentation (in-app)
- [ ] Icon and branding
- [ ] App signing and notarization

**Deliverable:** Beta-ready native macOS app

---

## Phase 3: Launch & Validate (Months 10-12)

**Goal:** Get first initial users, validate business model
**Timeline:** ~12 weeks (3 months)

### Month 10: Public Launch (Weeks 37-40)
- [ ] Landing page (value prop, pricing, download)
- [ ] Stripe integration (payment processing)
- [ ] Freemium limits (3 apps, 5 workflows)
- [ ] License validation (check Pro status)
- [ ] Product Hunt launch
- [ ] Open source MCP bridge announcement (HN, Reddit, Twitter)

**Target:** 1,000 downloads, 50 trial users

### Month 11: Community Feedback (Weeks 41-44)
- [ ] Content marketing (blog posts, use cases)
- [ ] YouTube demo video (3-5 minutes)
- [ ] Outreach to Mac productivity communities
- [ ] Support infrastructure (email, docs)
- [ ] Bug fixes based on user feedback

**Target:** initial users, 25 users (growth targets)

### Month 12: Iterate & Improve (Weeks 45-48)
- [ ] Feature improvements based on feedback
- [ ] Better onboarding (reduce friction)
- [ ] Performance optimization
- [ ] Additional app support (based on requests)
- [ ] Referral program (incentivize sharing)

**Target:** growing users, 50 users (growth targets)

**Decision point:** If growth targets achieved, proves business model. Continue to Phase 4. If not, pivot or adjust.

---

## Phase 4: Growth & Scale (Months 13-18)

**Goal:** Reach growth targets (growing user base)
**Timeline:** ~24 weeks (6 months)

### Months 13-15: Product Improvements
- [ ] Conversational workflow builder (AI assistant chat)
- [ ] Workflow sharing (import/export)
- [ ] Community workflows (library/marketplace)
- [ ] Scheduled workflows (run at specific times)
- [ ] Mac App Store submission (broader reach)

### Months 16-18: Marketing & Growth
- [ ] SEO content (blog posts for each app)
- [ ] YouTube tutorials (specific workflows)
- [ ] Partnerships (Mac productivity bloggers/YouTubers)
- [ ] Paid marketing (if profitable)
- [ ] User testimonials and case studies

**Target:** growing user base, growth targets

**Milestone:** This is sustainability. Can work on project full-time if desired, or hire help.

---

## Phase 5: Platform Expansion (Months 19-24+)

**Goal:** Multi-platform, advanced features, enterprise
**Timeline:** Ongoing, ongoing development

### Accessibility API Support (Tier 2)
- Support non-scriptable apps via macOS Accessibility APIs
- Expand coverage from 30-40% to 60-70% of apps
- Charge premium (subscription pricing tier)

### Windows Version
- Port discovery layer (COM introspection, registry)
- Windows platform adapter (PowerShell, COM execution)
- Windows UI (reuse Swift patterns or Electron)
- 14x market expansion

### Vision AI Support (Tier 3)
- Screenshot + vision AI for any visible app
- Most expensive tier (subscription pricing)
- Near-universal coverage (95%+ of apps)

### Enterprise Features
- Team sharing and collaboration
- Admin controls and compliance
- SSO/SAML integration
- Custom deployment
- Enterprise pricing

---

## Key Milestones & Metrics

| Milestone | Timeline | Metric | Target |
|-----------|----------|--------|--------|
| Technical validation | Month 1 | JITD proof of concept | Works with 1 app |
| Open source core | Month 5 | MCP bridge released | 100+ GitHub stars |
| Beta launch | Month 9 | Native app ready | 50 beta users |
| Public launch | Month 10 | Initial adoption | Initial validation |
| Product-market fit | Month 12 | Validation | 50 users, growth targets |
| Sustainability | Month 18 | Profitability | growing user base, growth targets |
| Scale | Month 24+ | Growth | 5,000 users, growth targets |

---

## Risk Mitigation

### Technical Risks
- **JITD doesn't work:** Prototype early (Phase 0 validates)
- **Hybrid architecture too complex:** Have Electron fallback plan
- **Apps don't work reliably:** Focus on most popular apps first

### Market Risks
- **No demand:** Free tier validates before building paid features
- **Can't monetize:** Pivot to developer tools (narrower but proven)
- **Too much competition:** Differentiate on native apps + local-first

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
- ✅ 100+ GitHub stars
- ✅ 10+ developers using it

### Phase 2 Success
- ✅ Native macOS app works well
- ✅ 50 beta users giving feedback
- ✅ Positive response (users want to pay)
- ✅ No critical bugs

### Phase 3 Success
- ✅ 50+ users
- ✅ product validation
- ✅ 70%+ retention
- ✅ Positive reviews/testimonials

### Phase 4 Success
- ✅ growth targets
- ✅ growing user base
- ✅ Sustainable business
- ✅ Can work full-time or hire help

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

**Status:** Ready to start Phase 0 (Technical Validation)
