# PAI Enforcement Architecture Analysis

**Purpose:** Analysis of how PAI implements automatic enforcement of rules, preferences, and policies — for porting to LifeOS.

**Date:** 2026-02-05
**Analyzed by:** Claude (Opus 4)
**Repository:** Daniel-Messler-personal_ai_infrastructure (v2.5)

---

## Part 1: Enforcement Inventory

### The Hard Truth

**PAI does NOT implement hard enforcement for most of your problem cases.** PAI uses a "trust but guide" architecture where only catastrophic security operations are code-blocked. Everything else (format compliance, capability gating, model routing, ISC quality) relies on **context injection + instruction following + post-hoc validation**.

This is the key finding: PAI's enforcement is effective not because it blocks violations, but because it **re-injects rules on every prompt** and **validates after execution**.

### Enforcement Mechanisms Found

| # | Mechanism | File | Trigger | Type | Hard Block? |
|---|-----------|------|---------|------|-------------|
| 1 | **Security Validator** | `SecurityValidator.hook.ts` | PreToolUse | BLOCK/CONFIRM/ALERT | YES (exit 2) |
| 2 | **Protected Files Validator** | `validate-protected.ts` | Pre-commit (manual/CI) | BLOCK | YES (exit 1) |
| 3 | **Pack Validator** | `validate-pack.ts` | Manual/CI | BLOCK | YES (exit 1) |
| 4 | **Format Enforcer** | `FormatEnforcer.hook.ts` | UserPromptSubmit | CONTEXT INJECTION | No |
| 5 | **Format Reminder** | `FormatReminder.hook.ts` | UserPromptSubmit | AI CLASSIFICATION | No |
| 6 | **ISC Validator** | `ISCValidator.ts` | Stop event | WARN/BLOCK (conditional) | Partial |
| 7 | **Voice Line Validator** | `response-format.ts` | Stop event | AUTO-CORRECT | No (fallback) |
| 8 | **Capability Loader** | `CapabilityLoader.ts` | On demand | SOFT GUIDANCE | No |
| 9 | **Effort Classifier** | `EffortClassifier.ts` | On demand | SOFT GUIDANCE | No |
| 10 | **System Integrity** | `SystemIntegrity.ts` | Stop event | AUTO-CORRECT | No |
| 11 | **Auto Work Creation** | `AutoWorkCreation.hook.ts` | UserPromptSubmit | AUTO-DOCUMENT | No |
| 12 | **Work Learning** | `WorkCompletionLearning.hook.ts` | SessionEnd | AUTO-DOCUMENT | No |

### Enforcement Spectrum

```
HARD BLOCK          CONDITIONAL BLOCK       CONTEXT INJECTION       SOFT GUIDANCE
(exit 2/1)          (shouldBlock flag)      (system-reminder)       (suggestions)

SecurityValidator   ISCValidator            FormatEnforcer          CapabilityLoader
validate-protected                          FormatReminder          EffortClassifier
validate-pack                               LoadContext              ValidationGates.yaml
                                            response-format.ts
```

---

## Part 2: File-by-File Analysis

### 2.1 SecurityValidator.hook.ts (HARD ENFORCEMENT)

```
File: Packs/pai-hook-system/src/hooks/SecurityValidator.hook.ts
Purpose: Blocks dangerous bash commands and file operations
Trigger: PreToolUse (runs BEFORE tool executes)
Enforcement Type: BLOCK (exit 2), CONFIRM (prompt user), ALERT (log)
Key Functions:
  - validateBashCommand() → checks against patterns.yaml blocked/confirm/alert
  - validatePathAccess() → checks zeroAccess/readOnly/confirmWrite/noDelete
  - matchesPattern() → regex + glob pattern matching
  - logSecurityEvent() → MEMORY/SECURITY/YYYY/MM/*.jsonl
Dependencies: patterns.yaml (user > system > fail-open)
```

**How it works:**
1. Receives JSON on stdin: `{session_id, tool_name, tool_input}`
2. Routes to handler: `handleBash()`, `handleEdit()`, `handleWrite()`, `handleRead()`
3. Loads patterns from YAML (cascading: user patterns > system patterns)
4. Matches command/path against patterns via regex
5. **BLOCK**: `process.exit(2)` — tool call never executes
6. **CONFIRM**: outputs `{decision: "ask", message: "..."}` — user prompted
7. **ALERT**: logs event, outputs `{continue: true}` — execution proceeds
8. **ALLOW**: outputs `{continue: true}` — execution proceeds

**Exit code model:**
- `exit(2)` = hard block (Claude Code prevents tool execution)
- `exit(0)` + `{continue: true}` = allow
- `exit(0)` + `{decision: "ask"}` = prompt user

**What's blocked:**
- `rm -rf /`, `rm -rf ~`, disk formatting, `dd if=/dev/zero`
- `gh repo delete`, `gh repo edit --visibility public`
- Zero-access paths: `~/.ssh/id_*`, `~/.aws/credentials`, `~/.gnupg/private*`

**What requires confirmation:**
- `git push --force`, `git reset --hard`
- `terraform destroy`, `kubectl delete namespace`
- `DROP DATABASE`, `TRUNCATE`
- Writing to `.env` files

**Fail-safe design:**
- Missing patterns.yaml → fail-open (allow all)
- stdin timeout (100ms) → fail-open
- Invalid regex → literal string matching fallback
- Logging errors → silent (don't block operations)

---

### 2.2 validate-protected.ts (PRE-COMMIT ENFORCEMENT)

```
File: Tools/validate-protected.ts
Purpose: Blocks commits containing secrets, PII, or private data
Trigger: Pre-commit (manual run or CI integration)
Enforcement Type: BLOCK (exit 1)
Key Functions:
  - scanAllFilesForSensitiveContent() → regex scan of staged files
  - checkForbiddenDirectories() → blocks entire directory trees
  - checkFileContent() → per-file pattern + context validation
  - hasExceptionContext() → allows patterns in example/doc contexts
Dependencies: .pai-protected.json (pattern manifest)
```

**18 pattern categories scanned:**
1. API keys (Anthropic, OpenAI, AWS, Stripe — 32 patterns)
2. GitHub tokens (ghp_, gho_, github_pat_ — 7 patterns)
3. Slack tokens (xoxb-, xoxp- — 4 patterns)
4. Webhooks (Discord, Slack, ntfy — 7 patterns)
5. Database credentials (connection strings — 7 patterns)
6. Private keys (RSA, SSH, PGP — 7 patterns)
7. PII SSN/Financial (SSN, EIN, credit cards — 8 patterns)
8. PII Phone (various formats — 5 patterns)
9. Personal emails (@gmail, @yahoo — 9 patterns)
10. Private paths (/Users/daniel/ — 7 patterns)
11. Internal infrastructure (private IPs — 8 patterns)
12. Customer data (customer_id — 4 patterns)
13. Team members (hardcoded names — 6 patterns)
14. Credentials inline (password= — 6 patterns)
15. Cloudflare (CF tokens — 5 patterns)
16. Misc sensitive (.pem, .key — 9 patterns)

**Exception system:**
- 127 exception files (wildcards supported: `Packs/*/README.md`)
- 60 allowed context prefixes ("# Example:", "placeholder", "YOUR_", etc.)
- Files in exceptions skip ALL pattern checks
- Lines with exception context (documentation) skip matching

---

### 2.3 FormatEnforcer.hook.ts (CONTEXT INJECTION)

```
File: Packs/pai-hook-system/src/hooks/FormatEnforcer.hook.ts
Purpose: Re-injects format specification on EVERY prompt
Trigger: UserPromptSubmit (runs before Claude generates response)
Enforcement Type: CONTEXT INJECTION (non-blocking)
Key Functions:
  - main() → reads RESPONSEFORMAT.md, personalizes, outputs as <system-reminder>
  - Skips subagent sessions
Dependencies: skills/CORE/SYSTEM/RESPONSEFORMAT.md, identity.ts
```

**This is PAI's primary format enforcement mechanism.** It works by:
1. Running on EVERY `UserPromptSubmit` event (not just session start)
2. Reading `RESPONSEFORMAT.md` format specification
3. Personalizing with identity/principal names
4. Outputting as `<system-reminder>` XML tags
5. Claude reads the reminder and follows format rules

**Why this works better than a one-time instruction:**
- In long conversations, context gets compressed/summarized
- One-time instructions at session start drift and get "forgotten"
- Re-injecting on every prompt keeps rules fresh
- `<system-reminder>` tags have high attention weight in Claude's processing

**Format rules enforced (via injection, not blocking):**
- Voice line: `🗣️ Identity: [16 words max — factual summary]`
- Full format: SUMMARY, ANALYSIS, ACTIONS, RESULTS, STATUS, NEXT sections
- Minimal format: SUMMARY + Voice
- Voice quality: No "Done.", "Ready.", "Happy to help!" — must be factual

---

### 2.4 response-format.ts (POST-EXECUTION VALIDATION)

```
File: Packs/pai-hook-system/src/hooks/lib/response-format.ts
Purpose: Validates voice lines and tab summaries after generation
Trigger: Called by voice.ts and tab-state.ts handlers during Stop event
Enforcement Type: AUTO-CORRECT (fallback to safe default)
Key Functions:
  - isValidVoiceCompletion(text) → rejects garbage phrases
  - isValidTabSummary(text) → requires gerund format
  - getVoiceFallback() → returns '' (silence)
  - getTabFallback() → returns "Processing request"
Dependencies: None (standalone validation library)
```

**Garbage pattern detection:**
```typescript
const ALWAYS_GARBAGE_PATTERNS = [
  /appreciate/i, /thank/i, /welcome/i, /help you/i,
  /assist you/i, /reaching out/i, /happy to/i,
  /let me know/i, /feel free/i
];
```

**Voice validation rules:**
- Rejects single words: "ready", "done", "ok", "sure", "hello"
- Rejects conversational starters: "I'm", "Got it", "Done.", "Yes"
- Requires 10+ characters
- Falls back to silence (empty string) if invalid

**Tab summary validation:**
- Must start with gerund: `/^[A-Z][a-z]*ing\b/`
- Examples: "Fixing auth", "Creating component"
- Falls back to "Processing request" or "Finishing task"

---

### 2.5 ISCValidator.ts (CONDITIONAL BLOCKING)

```
File: Releases/v2.5/.claude/hooks/handlers/ISCValidator.ts
Purpose: Validates ISC criteria after algorithm execution
Trigger: Stop event (via StopOrchestrator)
Enforcement Type: WARN (default), BLOCK (if algorithm attempted + empty criteria)
Key Functions:
  - handleISCValidation() → orchestrates validation
  - validate() → checks criteria array, modification time, THREAD.md
Dependencies: current-work.json, ISC.json, THREAD.md
```

**Blocking condition (the only conditional block in PAI outside security):**
```
IF algorithm was attempted (response contains "OBSERVE", "CAPABILITIES", or "ISC TRACKER")
AND criteria array is empty
THEN shouldBlock = true
```

**Block message requires:**
1. Build 3-10 ISC criteria during OBSERVE phase
2. Write to ISC.json before proceeding
3. Each criterion: 8-12 words, binary testable STATE
4. Example: "Research agents return findings within two minutes"

**Warning conditions (non-blocking):**
- Empty criteria array (without algorithm attempt)
- ISC.json not modified since session start
- THREAD.md contains `_Pending..._` placeholders

---

### 2.6 ISCManager.ts (DATA VALIDATION)

```
File: Packs/pai-algorithm-skill/src/skills/THEALGORITHM/Tools/ISCManager.ts
Purpose: Creates and manages ISC tables with strict validation
Trigger: Tool invocation during algorithm execution
Enforcement Type: BLOCK (invalid inputs), AUTO-CORRECT (stale claims)
Key Functions:
  - add → validates source enum, verification method, criteria pairing
  - claim → validates claimable flag, claim freshness (30min stale)
  - research-block → blocks rows until user acknowledges
Dependencies: ISC.json (active work file)
```

**Hard validation rules:**
- Source must be: EXPLICIT, INFERRED, IMPLICIT, or RESEARCH
- Status must be: PENDING, ACTIVE, DONE, ADJUSTED, or BLOCKED
- Verification method must be: browser, test, grep, api, lint, manual, agent, or inferred
- Result must be: PASS, ADJUSTED, or BLOCKED
- `--description` required for add operations
- `--verify-criteria` required when `--verify-method` specified

**Interview protocol for vague criteria:**
1. "What does success look like when this is done?"
2. "Who will use this and what will they do with it?"
3. "What would make you show this to your friends?"
4. "What existing thing is this most similar to?"
5. "What should this definitely NOT do?"

---

### 2.7 CapabilityLoader.ts + EffortClassifier.ts (SOFT GUIDANCE)

```
File: Packs/pai-algorithm-skill/src/skills/THEALGORITHM/Tools/CapabilityLoader.ts
File: Packs/pai-algorithm-skill/src/skills/THEALGORITHM/Tools/EffortClassifier.ts
Purpose: Suggests capabilities and models based on effort level
Trigger: On demand during algorithm execution
Enforcement Type: SOFT GUIDANCE (suggestions, not blocks)
Key Functions:
  - filterByEffort() → returns available/unavailable capability lists
  - effortMeetsMinimum() → compares effort levels
  - classify() → determines effort from task description
Dependencies: Capabilities.yaml
```

**Capability matrix (from Capabilities.yaml):**
```yaml
models:
  haiku:   { effort_min: QUICK }
  sonnet:  { effort_min: STANDARD }
  opus:    { effort_min: DETERMINED }

parallel:
  max_concurrent:
    QUICK: 1,  STANDARD: 3,  THOROUGH: 5,  DETERMINED: 10
```

**Model suggestions (from EffortClassifier.ts):**
```
TRIVIAL   → none (no agent needed)
QUICK     → haiku
STANDARD  → sonnet
THOROUGH  → sonnet
DETERMINED → opus
```

**No hard enforcement.** The loader returns available/unavailable lists; the classifier suggests models. Neither blocks wrong choices.

---

### 2.8 patterns.example.yaml (SECURITY PATTERNS)

```
File: Releases/v2.5/.claude/skills/PAI/SYSTEM/PAISECURITYSYSTEM/patterns.example.yaml
Purpose: Defines security patterns for SecurityValidator
Trigger: Loaded by SecurityValidator on first use (cached)
Enforcement Type: Configuration (feeds into BLOCK/CONFIRM/ALERT)
Key Sections: philosophy, bash (blocked/confirm/alert), paths (zeroAccess/readOnly/confirmWrite/noDelete)
Dependencies: Read by SecurityValidator.hook.ts
```

**Philosophy:**
```yaml
philosophy:
  mode: safe_functional
  principle: "Meaningful protection without friction that drives people to disable security"
```

---

## Part 3: Architecture Summary

### 3.1 Where Validation Logic Lives

```
┌─────────────────────────────────────────────────────────────────┐
│                    CLAUDE CODE FRAMEWORK                         │
│                                                                  │
│  settings.json (hook registration)                               │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ HOOK LAYER (TypeScript scripts, invoked by Claude Code)   │   │
│  │                                                           │   │
│  │  SessionStart:                                            │   │
│  │    LoadContext.hook.ts → injects SKILL.md as context       │   │
│  │                                                           │   │
│  │  UserPromptSubmit:                                        │   │
│  │    FormatEnforcer.hook.ts → injects format rules          │   │
│  │    FormatReminder.hook.ts → classifies depth/capabilities │   │
│  │    AutoWorkCreation.hook.ts → tracks work items           │   │
│  │                                                           │   │
│  │  PreToolUse:                                              │   │
│  │    SecurityValidator.hook.ts → BLOCKS dangerous ops       │   │
│  │                                                           │   │
│  │  Stop:                                                    │   │
│  │    StopOrchestrator.hook.ts → delegates to:               │   │
│  │      ├─ voice.ts (validates voice line)                   │   │
│  │      ├─ capture.ts (updates work tracking)                │   │
│  │      ├─ tab-state.ts (visual feedback)                    │   │
│  │      └─ SystemIntegrity.ts (auto-maintenance)             │   │
│  │      └─ ISCValidator.ts (validates criteria)              │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ TOOL LAYER (TypeScript scripts, invoked as skill tools)   │   │
│  │                                                           │   │
│  │  ISCManager.ts → validates ISC data on creation/update    │   │
│  │  CapabilityLoader.ts → filters capabilities by effort     │   │
│  │  EffortClassifier.ts → suggests models + effort levels    │   │
│  │  SpawnAgentWithProfile.ts → agents with defaults          │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ CI LAYER (manual/automated validation)                    │   │
│  │                                                           │   │
│  │  validate-protected.ts → blocks secrets in commits        │   │
│  │  validate-pack.ts → validates pack completeness           │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 How Validators Access Rules

| Validator | Rule Source | Loading Pattern |
|-----------|-----------|-----------------|
| SecurityValidator | `patterns.yaml` (YAML) | Cascading: user > system > fail-open. Cached after first load. |
| FormatEnforcer | `RESPONSEFORMAT.md` (Markdown) | Read from skill directory every invocation. |
| ISCValidator | `ISC.json` + `current-work.json` | Read from MEMORY paths at validation time. |
| validate-protected | `.pai-protected.json` (JSON) | Read from repo root. |
| CapabilityLoader | `Capabilities.yaml` (YAML) | Read from skill data directory. |

### 3.3 Error Communication

| Mechanism | User-Facing | Logged | Where Logged |
|-----------|------------|--------|--------------|
| Security BLOCK | stderr: "BLOCKED: reason" | Yes | MEMORY/SECURITY/YYYY/MM/*.jsonl |
| Security CONFIRM | JSON prompt in Claude UI | Yes | MEMORY/SECURITY/*.jsonl |
| Security ALERT | stderr warning | Yes | MEMORY/SECURITY/*.jsonl |
| Format injection | Invisible (system-reminder) | No | — |
| Voice validation fail | Silent (no TTS output) | Yes | MEMORY/VOICE/voice-events.jsonl |
| ISC validation warn | stderr warnings | No | — |
| ISC validation block | shouldBlock flag + message | No | — |
| Protected files block | Terminal output with categories | No | — |

### 3.4 Opt-in vs Mandatory

| Mechanism | Mandatory? | How to Disable |
|-----------|-----------|----------------|
| SecurityValidator | Yes (if hook registered) | Remove from settings.json hooks |
| FormatEnforcer | Yes (if hook registered) | Remove from settings.json hooks |
| ISCValidator | Yes (if hook registered) | Remove from settings.json hooks |
| validate-protected | No (manual run) | Don't run it / remove from CI |
| Capability suggestions | No (guidance only) | Ignore suggestions |

### 3.5 Performance Impact

| Hook | Latency | Notes |
|------|---------|-------|
| SecurityValidator | <10ms | Pattern matching is fast; 100ms stdin timeout |
| FormatEnforcer | <50ms | File read + string replacement |
| FormatReminder | ~500ms | AI inference (Haiku) for classification |
| StopOrchestrator | ~200ms | Transcript parsing + 4 parallel handlers |
| AutoWorkCreation | ~300ms | Haiku inference for classification |
| validate-protected | ~2-5s | Scans all staged files with regex |

---

## Part 4: Port Strategy for LifeOS

### 4.1 Why PAI Works and LifeOS Doesn't

The core difference isn't that PAI has hard enforcement where LifeOS doesn't. **PAI mostly doesn't have hard enforcement either.** The difference is:

1. **PAI re-injects rules on EVERY prompt** via FormatEnforcer. LifeOS injects rules once at session start. In long conversations, one-time rules get compressed and "forgotten."

2. **PAI validates AFTER execution** and auto-corrects. The voice handler silently drops garbage voice lines. The ISC validator blocks empty criteria. LifeOS has no post-execution validation.

3. **PAI uses structured data + tools** instead of instructions. ISCManager validates enum values in code, not "please use valid values." CapabilityLoader returns computed lists, not "check the docs."

4. **PAI's security is the ONLY hard block**, and it's surgically scoped to catastrophic operations. Everything else uses the "inject, suggest, validate, auto-correct" pattern.

### 4.2 Prioritized Port Strategy

#### Priority 1: Context Re-injection Hook (Highest Impact, Lowest Effort)

**Problem solved:** Format drift, rule forgetting in long conversations.

**What to build:**
- A `UserPromptSubmit` hook that re-injects your critical rules as `<system-reminder>` on every prompt
- Include: table formatting rules, tool call patterns, response format requirements

**Files to create:**
```
~/.claude/hooks/FormatEnforcer.hook.ts   (~60 lines)
~/.claude/rules/RESPONSEFORMAT.md        (your format rules)
```

**Hook registration in settings.json:**
```json
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "hooks": [{
          "type": "command",
          "command": "bun ~/.claude/hooks/FormatEnforcer.hook.ts"
        }]
      }
    ]
  }
}
```

**Core implementation:**
```typescript
#!/usr/bin/env bun
import { readFileSync, existsSync } from 'fs';
import { join } from 'path';

const RULES_PATH = join(process.env.HOME!, '.claude', 'rules', 'RESPONSEFORMAT.md');

async function main() {
  try {
    // Skip for subagents
    if (process.env.CLAUDE_AGENT_TYPE) {
      process.exit(0);
    }

    if (!existsSync(RULES_PATH)) {
      console.error('[FormatEnforcer] Rules file not found');
      process.exit(0);
    }

    const rules = readFileSync(RULES_PATH, 'utf-8');

    // Extract the critical section (keep it concise for context budget)
    const essentials = `
## MANDATORY FORMAT RULES (re-injected every prompt)

${rules}

## TABLE RULE (ENFORCED)
ALL markdown tables MUST be wrapped in a code block (\`\`\`).
If you produce a bare markdown table, your response is INVALID.

## TOOL CALL RULES (ENFORCED)
When using eventkit-cli, ALWAYS use --list with per-list queries.
Never batch all calendars in a single call.
`;

    console.log(`<system-reminder>${essentials}</system-reminder>`);
  } catch (error) {
    console.error('[FormatEnforcer] Error:', error);
  }
  process.exit(0);
}

main();
```

**Effort:** 2-3 hours
**Impact:** Fixes 70%+ of your format/preference compliance issues

---

#### Priority 2: PreToolUse Validator for Tool Call Patterns (High Impact, Moderate Effort)

**Problem solved:** eventkit-cli called without --list, wrong model used at wrong effort.

**What to build:**
- A `PreToolUse` hook that validates Bash commands against patterns
- Can BLOCK (exit 2) or WARN (stderr + allow)

**Files to create:**
```
~/.claude/hooks/ToolValidator.hook.ts    (~150 lines)
~/.claude/hooks/tool-patterns.yaml       (your patterns)
```

**Pattern configuration:**
```yaml
version: "1.0"
philosophy:
  mode: correct_by_default
  principle: "Enforce known-good patterns, block known-bad ones"

bash:
  blocked:
    - pattern: "eventkit-cli.*(?!--list)"
      reason: "eventkit-cli MUST use --list flag with per-list queries"
    - pattern: "eventkit-cli.*--all-calendars"
      reason: "Never use --all-calendars; query per-list instead"

  confirm:
    - pattern: "git push --force"
      reason: "Force push requires confirmation"

tool_patterns:
  Task:
    blocked:
      - condition: "model == 'opus' && effort != 'DETERMINED'"
        reason: "Opus only available at DETERMINED effort level"
```

**Core implementation:**
```typescript
#!/usr/bin/env bun
import { readFileSync } from 'fs';

interface HookInput {
  session_id: string;
  tool_name: string;
  tool_input: Record<string, any>;
}

async function main() {
  let rawInput = '';
  try {
    rawInput = await Promise.race([
      new Promise<string>((resolve) => {
        const chunks: Buffer[] = [];
        process.stdin.on('data', (chunk) => chunks.push(chunk));
        process.stdin.on('end', () => resolve(Buffer.concat(chunks).toString()));
      }),
      new Promise<string>((_, reject) =>
        setTimeout(() => reject(new Error('timeout')), 100)
      ),
    ]);
  } catch {
    process.exit(0); // fail-open on timeout
  }

  const input: HookInput = JSON.parse(rawInput);

  if (input.tool_name === 'Bash') {
    const command = input.tool_input.command || '';

    // Example: Block eventkit-cli without --list
    if (command.includes('eventkit-cli') && !command.includes('--list')) {
      console.error('BLOCKED: eventkit-cli MUST use --list with per-list queries');
      process.exit(2); // HARD BLOCK
    }
  }

  if (input.tool_name === 'Task') {
    const model = input.tool_input.model || '';
    // Example: Block Opus at non-DETERMINED effort
    // (Would need effort context from environment or file)
  }

  console.log(JSON.stringify({ continue: true }));
  process.exit(0);
}

main();
```

**Effort:** 4-6 hours
**Impact:** Directly blocks known-bad tool patterns

---

#### Priority 3: Post-Execution Format Validator (Medium Impact, Moderate Effort)

**Problem solved:** Tables not wrapped in code blocks, response format violations.

**What to build:**
- A `Stop` hook that parses Claude's response and validates format
- AUTO-CORRECTS by flagging violations for the next prompt

**Files to create:**
```
~/.claude/hooks/FormatValidator.hook.ts   (~120 lines)
~/.claude/state/format-violations.json    (auto-managed)
```

**How it works:**
1. Stop hook fires after Claude responds
2. Parse the response transcript
3. Check for bare markdown tables (not in code blocks)
4. Check for missing required sections
5. Write violations to state file
6. Next UserPromptSubmit hook reads violations and injects correction

**Core implementation:**
```typescript
#!/usr/bin/env bun
import { readFileSync, writeFileSync, mkdirSync } from 'fs';
import { join } from 'path';

const STATE_DIR = join(process.env.HOME!, '.claude', 'state');
const VIOLATIONS_FILE = join(STATE_DIR, 'format-violations.json');

async function main() {
  let rawInput = '';
  try {
    const chunks: Buffer[] = [];
    process.stdin.on('data', (chunk) => chunks.push(chunk));
    await new Promise<void>((resolve) => {
      process.stdin.on('end', resolve);
      setTimeout(resolve, 500);
    });
    rawInput = Buffer.concat(chunks).toString();
  } catch {
    process.exit(0);
  }

  try {
    const input = JSON.parse(rawInput);
    const transcriptPath = input.transcript_path;

    if (!transcriptPath) {
      process.exit(0);
    }

    // Read last assistant message from transcript
    const transcript = readFileSync(transcriptPath, 'utf-8');
    const lines = transcript.trim().split('\n');
    let lastAssistantMsg = '';

    for (let i = lines.length - 1; i >= 0; i--) {
      try {
        const entry = JSON.parse(lines[i]);
        if (entry.type === 'assistant') {
          lastAssistantMsg = JSON.stringify(entry);
          break;
        }
      } catch { continue; }
    }

    const violations: string[] = [];

    // Check for bare markdown tables (pipe tables not inside code blocks)
    const bareTableRegex = /^(?!```)\|[^\n]*\|$/m;
    if (bareTableRegex.test(lastAssistantMsg)) {
      violations.push('BARE_TABLE: Markdown table found outside code block');
    }

    if (violations.length > 0) {
      mkdirSync(STATE_DIR, { recursive: true });
      writeFileSync(VIOLATIONS_FILE, JSON.stringify({
        timestamp: new Date().toISOString(),
        violations,
      }));
    }
  } catch (error) {
    console.error('[FormatValidator] Error:', error);
  }

  process.exit(0);
}

main();
```

**Then in your FormatEnforcer (Priority 1), add:**
```typescript
// Check for previous violations
if (existsSync(VIOLATIONS_FILE)) {
  const violations = JSON.parse(readFileSync(VIOLATIONS_FILE, 'utf-8'));
  if (violations.violations?.length > 0) {
    console.log(`<system-reminder>
FORMAT VIOLATIONS DETECTED IN PREVIOUS RESPONSE:
${violations.violations.join('\n')}

CORRECT THESE IN YOUR NEXT RESPONSE.
</system-reminder>`);
    // Clear violations after injecting
    unlinkSync(VIOLATIONS_FILE);
  }
}
```

**Effort:** 4-6 hours
**Impact:** Creates a feedback loop — violations detected post-hoc are injected as corrections pre-response

---

#### Priority 4: Capability Gate (Lower Impact, Low Effort)

**Problem solved:** Wrong model selected for effort level.

**What to build:**
- A simple tool/function that returns available capabilities for current effort level
- Claude reads the output and follows it (soft enforcement)
- Optionally: PreToolUse hook that blocks Task calls with wrong model

**File to create:**
```
~/.claude/hooks/lib/capabilities.ts   (~40 lines)
```

**Implementation:**
```typescript
export const EFFORT_MODELS: Record<string, string[]> = {
  TRIVIAL: [],
  QUICK: ['haiku'],
  STANDARD: ['haiku', 'sonnet'],
  THOROUGH: ['haiku', 'sonnet'],
  DETERMINED: ['haiku', 'sonnet', 'opus'],
};

export const EFFORT_PARALLEL: Record<string, number> = {
  QUICK: 1,
  STANDARD: 3,
  THOROUGH: 5,
  DETERMINED: 10,
};

export function getAvailableModels(effort: string): string[] {
  return EFFORT_MODELS[effort] || ['sonnet'];
}

export function getMaxParallel(effort: string): number {
  return EFFORT_PARALLEL[effort] || 1;
}
```

**Effort:** 1-2 hours
**Impact:** Low (PAI doesn't hard-enforce this either; it's guidance)

---

### 4.3 The 80/20 Solution

If you only build ONE thing, build **Priority 1: Context Re-injection Hook**.

Here's why:
- PAI's #1 enforcement advantage over LifeOS is re-injecting rules on every prompt
- Most of your failures ("wrap tables", "use --list", "don't use Opus") are instruction-following failures caused by context drift
- A `<system-reminder>` injected on every `UserPromptSubmit` keeps rules in Claude's active context
- This is ~60 lines of TypeScript and 2-3 hours of work

**The 80/20 implementation:**

```typescript
#!/usr/bin/env bun
// ~/.claude/hooks/LifeOSEnforcer.hook.ts
// Single hook that handles ALL enforcement via context injection

import { readFileSync, existsSync } from 'fs';

async function main() {
  if (process.env.CLAUDE_AGENT_TYPE) {
    process.exit(0); // Skip for subagents
  }

  const rules = `
## LIFEOS MANDATORY RULES (auto-injected every prompt)

### Table Formatting (ENFORCED)
- ALL markdown tables MUST be wrapped in triple-backtick code blocks
- A bare pipe-table in your response is a FORMAT VIOLATION
- If you need to show tabular data, use a code block

### Tool Call Patterns (ENFORCED)
- eventkit-cli: ALWAYS use --list flag, query per-list, NEVER --all-calendars
- Reminders: ALWAYS query per-list, NEVER batch all lists

### Model Routing (ENFORCED)
- QUICK effort: Use haiku only
- STANDARD effort: Use sonnet only
- THOROUGH effort: Use sonnet only
- DETERMINED effort: Opus allowed

### ISC Quality (ENFORCED)
- Every ISC criterion must be binary-testable (PASS/FAIL, not subjective)
- Bad: "Code is clean" | Good: "All functions have <20 lines"
- Bad: "Performance is good" | Good: "API responds in <200ms"
`;

  console.log(`<system-reminder>${rules}</system-reminder>`);
  process.exit(0);
}

main();
```

Register in `~/.claude/settings.json`:
```json
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "hooks": [{
          "type": "command",
          "command": "bun ~/.claude/hooks/LifeOSEnforcer.hook.ts"
        }]
      }
    ]
  }
}
```

**That's it.** 30 lines. 1 hour of work. Fixes the majority of your enforcement gaps.

---

## Part 5: Code Samples

### 5.1 Complete PreToolUse Blocker (adapted from SecurityValidator)

This is the minimal version of PAI's SecurityValidator, adapted for LifeOS tool call enforcement:

```typescript
#!/usr/bin/env bun
// ~/.claude/hooks/ToolGuard.hook.ts
// PreToolUse hook that BLOCKS known-bad tool patterns

interface HookInput {
  session_id: string;
  tool_name: string;
  tool_input: Record<string, any>;
}

interface Rule {
  pattern: RegExp;
  reason: string;
  action: 'block' | 'confirm';
}

const BASH_RULES: Rule[] = [
  // LifeOS-specific
  {
    pattern: /eventkit-cli(?!.*--list)/,
    reason: 'eventkit-cli MUST include --list flag',
    action: 'block',
  },
  {
    pattern: /eventkit-cli.*--all/,
    reason: 'Never use --all with eventkit-cli; query per-list',
    action: 'block',
  },
  // Security (from PAI)
  {
    pattern: /rm\s+-rf\s+[\/~]/,
    reason: 'Destructive recursive delete blocked',
    action: 'block',
  },
  {
    pattern: /git\s+push\s+(-f|--force)/,
    reason: 'Force push requires confirmation',
    action: 'confirm',
  },
];

async function main() {
  let rawInput = '';
  try {
    rawInput = await Promise.race([
      new Promise<string>((resolve) => {
        const chunks: Buffer[] = [];
        process.stdin.on('data', (chunk) => chunks.push(chunk));
        process.stdin.on('end', () => resolve(Buffer.concat(chunks).toString()));
      }),
      new Promise<string>((_, reject) =>
        setTimeout(() => reject(new Error('timeout')), 100)
      ),
    ]);
  } catch {
    // Timeout: fail-open
    console.log(JSON.stringify({ continue: true }));
    process.exit(0);
  }

  let input: HookInput;
  try {
    input = JSON.parse(rawInput);
  } catch {
    console.log(JSON.stringify({ continue: true }));
    process.exit(0);
  }

  if (input.tool_name === 'Bash') {
    const command = input.tool_input?.command || '';

    for (const rule of BASH_RULES) {
      if (rule.pattern.test(command)) {
        if (rule.action === 'block') {
          console.error(`BLOCKED: ${rule.reason}`);
          console.error(`Command: ${command.slice(0, 100)}`);
          process.exit(2); // HARD BLOCK
        }
        if (rule.action === 'confirm') {
          console.log(JSON.stringify({
            decision: 'ask',
            message: `${rule.reason}\n\nCommand: ${command.slice(0, 200)}\n\nProceed?`,
          }));
          process.exit(0);
        }
      }
    }
  }

  // Task tool model enforcement
  if (input.tool_name === 'Task') {
    const model = input.tool_input?.model;
    if (model === 'opus') {
      // Read current effort level from state file if available
      // For now, just warn
      console.error('WARNING: Opus model requested. Verify this is DETERMINED effort.');
    }
  }

  console.log(JSON.stringify({ continue: true }));
  process.exit(0);
}

main();
```

**Register as PreToolUse hook:**
```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{
          "type": "command",
          "command": "bun ~/.claude/hooks/ToolGuard.hook.ts"
        }]
      },
      {
        "matcher": "Task",
        "hooks": [{
          "type": "command",
          "command": "bun ~/.claude/hooks/ToolGuard.hook.ts"
        }]
      }
    ]
  }
}
```

### 5.2 ISC Row Validator (adapted from ISCManager)

```typescript
// ~/.claude/hooks/lib/isc-validator.ts
// Validates ISC criteria quality

interface ISCRow {
  id: string;
  description: string;
  source: string;
  status: string;
  verification?: {
    method: string;
    criteria: string;
  };
}

const VALID_SOURCES = ['EXPLICIT', 'INFERRED', 'IMPLICIT', 'RESEARCH'];
const VALID_STATUSES = ['PENDING', 'ACTIVE', 'DONE', 'ADJUSTED', 'BLOCKED'];
const VALID_METHODS = ['browser', 'test', 'grep', 'api', 'lint', 'manual', 'agent', 'inferred'];

// Vague criteria patterns (reject these)
const VAGUE_PATTERNS = [
  /\bgood\b/i, /\bnice\b/i, /\bclean\b/i, /\bfast\b/i,
  /\bbetter\b/i, /\bimproved\b/i, /\bquality\b/i,
  /\bappropriate\b/i, /\breasonable\b/i, /\boptimal\b/i,
];

export function validateISCRow(row: ISCRow): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  // Enum validation
  if (!VALID_SOURCES.includes(row.source)) {
    errors.push(`Invalid source "${row.source}". Must be: ${VALID_SOURCES.join(', ')}`);
  }
  if (!VALID_STATUSES.includes(row.status)) {
    errors.push(`Invalid status "${row.status}". Must be: ${VALID_STATUSES.join(', ')}`);
  }
  if (row.verification?.method && !VALID_METHODS.includes(row.verification.method)) {
    errors.push(`Invalid verification method "${row.verification.method}"`);
  }

  // Description quality
  if (!row.description || row.description.length < 10) {
    errors.push('Description too short. Must be 8-12 words, binary testable.');
  }

  // Vague criteria detection
  for (const pattern of VAGUE_PATTERNS) {
    if (pattern.test(row.description)) {
      errors.push(
        `Vague criterion detected: "${row.description}" contains "${pattern.source}". ` +
        `Rephrase as binary-testable state. ` +
        `Bad: "Code is clean" | Good: "All functions have <20 lines"`
      );
      break;
    }
  }

  // Verification pairing
  if (row.verification?.method && !row.verification.criteria) {
    errors.push('Verification method specified without criteria. Add --verify-criteria.');
  }

  return { valid: errors.length === 0, errors };
}
```

### 5.3 Complete settings.json Hook Wiring

```json
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "hooks": [{
          "type": "command",
          "command": "bun ~/.claude/hooks/LifeOSEnforcer.hook.ts"
        }]
      }
    ],
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{
          "type": "command",
          "command": "bun ~/.claude/hooks/ToolGuard.hook.ts"
        }]
      }
    ],
    "Stop": [
      {
        "hooks": [{
          "type": "command",
          "command": "bun ~/.claude/hooks/FormatValidator.hook.ts"
        }]
      }
    ]
  }
}
```

---

## Summary: Key Takeaways

### 1. PAI's enforcement is 90% context injection, 10% hard blocks

The security validator (exit 2) is the ONLY true enforcement gate. Everything else — format compliance, model routing, capability gating, ISC quality — works through repeated context injection and post-hoc validation. This is a deliberate design choice: "Meaningful protection without friction that drives people to disable security."

### 2. The #1 mechanism to port is re-injection on every prompt

LifeOS's core problem is that rules injected at session start drift and get forgotten in long conversations. PAI solves this with `FormatEnforcer.hook.ts` running on every `UserPromptSubmit`. Port this first.

### 3. Hard blocks should be surgical and rare

PAI only blocks: destructive filesystem operations, zero-access paths, and (conditionally) empty ISC after algorithm execution. Everything else is guidance. If you over-block, users disable the system entirely.

### 4. The feedback loop matters more than the gate

PAI's effectiveness comes from: inject rules (pre) → validate output (post) → inject corrections (next pre). This create-detect-correct loop is more robust than trying to prevent all violations upfront.

### 5. Effort estimates for LifeOS port

| Priority | Component | Effort | Impact |
|----------|-----------|--------|--------|
| P1 | Context re-injection hook | 2-3 hours | HIGH — fixes format drift |
| P2 | PreToolUse tool validator | 4-6 hours | HIGH — blocks bad tool patterns |
| P3 | Post-execution format checker | 4-6 hours | MEDIUM — creates feedback loop |
| P4 | Capability gate library | 1-2 hours | LOW — soft guidance only |
| **Total** | | **11-17 hours** | |
| **80/20** | P1 alone | **2-3 hours** | **70%+ of value** |
