# GitHub Issue Labeling Strategy

**Project:** IAC MCP Bridge (JITD Engine)
**Date:** 2026-01-16
**Status:** Active

## Overview

This document defines the labeling strategy for GitHub issues in the IAC MCP Bridge project. Well-structured labels improve discoverability, enable efficient sprint planning, and help track progress across different workstreams.

## Label Categories

### 1. Priority Labels

Priority labels indicate urgency and impact. **Every issue should have exactly one priority label.**

| Label | Description | Use When |
|-------|-------------|----------|
| `priority/p0` | Critical - blocks release or other work | Security issues, data corruption, breaks core functionality |
| `priority/p1` | High priority - address soon | Major features, important bugs, sprint commitments |
| `priority/p2` | Medium priority - nice to have | Improvements, workarounds exist, future enhancements |
| `priority/p3` | Backlog - someday/maybe | Ideas, minor improvements, long-term vision items |

**Color scheme:**
- `priority/p0`: `#ff0000` (red)
- `priority/p1`: `#ff6600` (orange)
- `priority/p2`: `#ffbb00` (amber)
- `priority/p3`: `#ffd700` (yellow)

### 2. Workstream Labels

Workstream labels identify the functional area of work. Issues can have **0-2 workstream labels** (some issues span multiple areas).

| Label | Description | Examples |
|-------|-------------|----------|
| `workstream/jitd` | JITD engine: discovery, parsing, tool generation | SDEF parsing, tool generation, type mapping |
| `workstream/mcp-server` | MCP server implementation | MCP protocol, stdio transport, tool/resource handlers |
| `workstream/macos-adapter` | macOS platform adapter | JXA execution, AppleEvents, app automation |
| `workstream/permissions` | Permission system | Permission checks, user prompts, safety rules |
| `workstream/testing` | Test infrastructure and test cases | Unit tests, integration tests, test harness |
| `workstream/documentation` | Documentation and planning | README, planning docs, API docs, guides |
| `workstream/build-tooling` | Build system and dependencies | npm scripts, TypeScript config, CI/CD |

**Color scheme:** All workstream labels use `#0052CC` (blue)

**Creating new workstreams:**
- Search existing labels first with `gh label list`
- Only create if no existing label fits
- Use format: `workstream/descriptive-name`
- Document rationale in this file

### 3. Type Labels

Type labels classify the nature of the work. **Every issue should have exactly one type label.**

| Label | Description | Examples |
|-------|-------------|----------|
| `type/bug` | Defect in existing functionality | Crashes, incorrect behavior, test failures |
| `type/enhancement` | New feature or capability | New commands, new functionality, feature additions |
| `type/tech-debt` | Code quality, refactoring, architecture | Refactoring, DRY violations, architectural improvements |
| `type/documentation` | Documentation improvements | README updates, planning docs, code comments |
| `type/testing` | Test coverage or test infrastructure | Writing tests, test utilities, test data |

**Color scheme:**
- `type/bug`: `#d73a4a` (red)
- `type/enhancement`: `#a2eeef` (light blue)
- `type/tech-debt`: `#ffeaa7` (yellow-orange)
- `type/documentation`: `#0075ca` (blue)
- `type/testing`: `#ffeaa7` (yellow-orange)

### 4. Scope Labels

Scope labels estimate effort. **Priority 0 and 1 issues should have a scope label** for sprint planning.

| Label | Description | Time Estimate |
|-------|-------------|---------------|
| `scope/small` | Quick win, obvious solution | < 4 hours |
| `scope/medium` | Requires design work | 1-2 weeks |
| `scope/large` | Multi-week effort | 2+ weeks |

**Color scheme:** All scope labels use `#84B6EB` (light blue)

### 5. Status Labels

Status labels track special states. **Use sparingly** - most issues don't need status labels.

| Label | Description | Use When |
|-------|-------------|----------|
| `status/needs-triage` | Needs evaluation and labeling | New issues not yet reviewed |
| `status/blocked` | Cannot proceed until dependency resolved | Waiting on external library, upstream fix, design decision |
| `status/deferred` | Intentionally postponed | Post-MVP, future phase, not now |
| `status/decision-needed` | Requires architectural decision | Multiple approaches possible, needs discussion |

**Color scheme:** All status labels use `#D4C5F9` (purple)

## Labeling Guidelines

### When Creating Issues

**Required:**
- At least 1 `priority/*` label
- At least 1 `type/*` label

**Recommended:**
- 1-2 `workstream/*` labels if issue belongs to established domain
- 1 `scope/*` label for P0/P1 issues (for sprint planning)

**Optional:**
- `status/*` labels as needed

### Example Well-Labeled Issues

**Example 1: Bug Fix**
```
Title: SDEF parser crashes on empty enumeration elements
Labels: priority/p1, workstream/jitd, type/bug, scope/small
```

**Example 2: Feature Request**
```
Title: Add support for Windows PowerShell automation
Labels: priority/p3, workstream/macos-adapter, type/enhancement, scope/large, status/deferred
```

**Example 3: Technical Debt**
```
Title: Refactor TypeMapper to use visitor pattern
Labels: priority/p2, workstream/jitd, type/tech-debt, scope/medium
```

**Example 4: Multi-Workstream Issue**
```
Title: Implement end-to-end Finder automation with permission checks
Labels: priority/p1, workstream/jitd, workstream/mcp-server, workstream/permissions, type/enhancement, scope/large
```

## Filtering Use Cases

### Sprint Planning Queries

**Quick wins for new contributors:**
```
label:scope/small -label:status/blocked
```

**Current sprint P0/P1 work:**
```
label:priority/p0,priority/p1 -label:status/blocked -label:status/deferred
```

**JITD engine progress:**
```
label:workstream/jitd is:open
```

### Domain-Specific Queries

**All MCP server work:**
```
label:workstream/mcp-server
```

**Permission system architecture:**
```
label:workstream/permissions label:status/decision-needed
```

**Test coverage gaps:**
```
label:type/testing label:workstream/testing
```

### Quality Tracking

**Open bugs by priority:**
```
label:type/bug label:priority/p0
label:type/bug label:priority/p1
```

**Technical debt (refactoring):**
```
label:type/tech-debt
```

## Maintenance

### Label Review Cadence

**Weekly:** Review newly created issues, ensure priority + type labels
**Monthly:** Audit for unlabeled issues, ensure workstream coverage
**Quarterly:** Review label usage, retire unused labels, propose new ones

### Label Retirement Policy

A label can be retired if:
- No issues have used it in 3+ months
- The domain it represents has been completed
- It has been superseded by a better label

Before retiring, re-label affected issues and document reason in this file.

### Creating New Labels

When creating a new label:

1. **Check existing labels first:**
   ```bash
   gh label list
   ```

2. **Create with consistent naming:**
   ```bash
   # Priority labels
   gh label create "priority/p3" --description "Backlog - someday/maybe" --color "ffd700"

   # Workstream labels
   gh label create "workstream/new-area" --description "Description of area" --color "0052CC"

   # Type labels
   gh label create "type/category" --description "Description" --color "appropriate-color"

   # Scope labels
   gh label create "scope/size" --description "Time estimate" --color "84B6EB"

   # Status labels
   gh label create "status/state" --description "Description" --color "D4C5F9"
   ```

3. **Document rationale:** Update this file with the new label's purpose and usage

## Current Label Set

**Priority Labels (4):**
- `priority/p0`, `priority/p1`, `priority/p2`, `priority/p3`

**Workstream Labels (7):**
- `workstream/jitd`
- `workstream/mcp-server`
- `workstream/macos-adapter`
- `workstream/permissions`
- `workstream/testing`
- `workstream/documentation`
- `workstream/build-tooling`

**Type Labels (5):**
- `type/bug`
- `type/enhancement`
- `type/tech-debt`
- `type/documentation`
- `type/testing`

**Scope Labels (3):**
- `scope/small`
- `scope/medium`
- `scope/large`

**Status Labels (4):**
- `status/needs-triage`
- `status/blocked`
- `status/deferred`
- `status/decision-needed`

**Total: 23 labels**

## Phase-Specific Considerations

### Phase 0: Technical Validation (Current)
Focus on:
- `workstream/jitd` (SDEF parsing, tool generation)
- `workstream/mcp-server` (basic protocol)
- Quick wins and P0/P1 bugs

### Phase 1: MVP
Add focus on:
- `workstream/macos-adapter` (JXA execution)
- `workstream/permissions` (safety system)
- Integration testing

### Phase 2+: Native UI
May add new workstreams:
- `workstream/swift-ui`
- `workstream/workflow-builder`
- `workstream/ipc` (Swift ↔ Node.js bridge)

## Related Documentation

- **Issue Template**: `.github/ISSUE_TEMPLATE.md` (when created)
- **Contributing Guide**: `CONTRIBUTING.md` (when created)
- **Project Structure**: `CLAUDE.md`
- **Roadmap**: `planning/ROADMAP.md`

---

**Last Updated:** 2026-01-16
**Next Review:** 2026-02-16 (monthly)
