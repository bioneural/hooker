<h1 align="center">
  h o o k e r
  <br>
  <sub>declarative policy enforcement for claude code hooks</sub>
</h1>

Agents do not possess discipline. They possess prompts. Prompts degrade — silently, inevitably, without consequence. hooker eliminates the prompt layer as an enforcement surface. What cannot be bypassed cannot be forgotten.

## The Problem

You write a rule in CLAUDE.md: "never force push to main." The agent obeys for a while. Then it forgets. Then you remind it. Then it forgets again. The failure mode is silent — no error, no warning. Gradual drift from intent.

Prompts are suggestions. hooker makes rules structural.

## What It Does

hooker sits between Claude Code and its tool calls. Every tool invocation passes through hooker before execution. Three outcomes are possible: **allow**, **deny**, or **transform**.

Three policy types:

- **Gate** — blocks actions that match a pattern. Regex. Deterministic. Microseconds. The first matching gate terminates evaluation.
- **Transform** — rewrites the action via a side-channel `claude -p` call. The rewrite occurs outside the main agent's context window — the agent sees the result, never the logic. Zero token pollution.
- **Inject** — surfaces context before the agent reasons. The information is present because the system placed it there, not because the agent chose to retrieve it.

Any policy can include a **classifier** — a local LLM gate via ollama. The classifier evaluates whether the policy should fire. It runs after pattern matching, before execution. Local inference. No remote API cost.

## What It Does Not Do

hooker is a policy layer, not a security boundary. Every error path fails open. If hooker cannot determine the correct action, it permits the action. A broken policy engine must not become a denial-of-service on the agent it governs.

hooker is stateless. It spawns per event, evaluates, exits. No daemon. No persistence. No retained context between invocations.

## Quick Start

Clone the repo:

```bash
git clone git@github.com:bioneural/hooker.git
```

Wire hooker into your project's `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Edit|Write",
        "hooks": [
          {
            "type": "command",
            "command": "/path/to/hooker/bin/hooker",
            "timeout": 30
          }
        ]
      }
    ],
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "/path/to/hooker/bin/hooker",
            "timeout": 30
          }
        ]
      }
    ]
  }
}
```

Define policies in `.claude/policies.yaml` at your project root:

```yaml
policies:
  - name: no force push
    event: PreToolUse
    tool: Bash
    match: ":git_push_force"
    type: gate
    message: "Force push is not allowed."
```

That is a complete, working policy. Force pushes are now structurally denied. The `:git_push_force` constant handles command variations the agent may generate (like `git -C /path push --force`) — no regex knowledge required.

## Examples

Block edits to sensitive files:

```yaml
  - name: no env edits
    event: PreToolUse
    tool: Edit|Write
    match_field: file_path
    match: "\\.env"
    type: gate
    message: "Modifying .env files is prohibited."
```

Rewrite commit messages to follow a project convention:

```yaml
  - name: conventional commits
    event: PreToolUse
    tool: Bash
    match: ":git_commit"
    type: transform
    context:
      - COMMIT_STYLE.md
    prompt: >
      Rewrite this commit message to follow the conventions in
      COMMIT_STYLE.md. Preserve technical content. Return only
      the complete git commit command.
```

Enforce a license header on new Python files (`transform_field` targets `content` while matching on `file_path`):

```yaml
  - name: license header
    event: PreToolUse
    tool: Write
    match_field: file_path
    match: "\\.py$"
    transform_field: content
    type: transform
    context:
      - LICENSE_HEADER.txt
    prompt: >
      If this file does not already begin with the license header from
      LICENSE_HEADER.txt, prepend it. Return only the file content.
```

`transform_field` is critical here — the policy matches on `file_path` to detect `.py` files, but the transform must write to `content`. Without `transform_field`, the rewritten content would overwrite the file path.

Surface a review panel for architectural decisions, gated by a local classifier:

```yaml
  - name: panel escalation
    event: UserPromptSubmit
    type: inject
    classifier:
      model: gemma3:1b
      prompt: >
        You are a classifier. Respond "yes" if the prompt involves
        architectural decisions, design tradeoffs, or novel problems.
        Otherwise respond "no". Output only "yes" or "no".
    context:
      - REVIEW_PANEL.md
```

## Architecture

hooker reads a JSON event from stdin. It parses the event, extracts `cwd`, and traverses upward from that directory to locate `.claude/policies.yaml`. If no policies file exists, the action is allowed. Exit.

Each policy is evaluated in declaration order. Three conditions are AND-ed:

1. **Event type** — exact match against `hook_event_name`. Optional. Omit to match all events.
2. **Tool name** — anchored regex (`\A(?:pattern)\z`) against `tool_name`. Optional. Only meaningful for `PreToolUse`.
3. **Content pattern** — unanchored regex against the resolved match field. Optional. Omit to match all content.

Omitting any condition means it matches everything. Policies that satisfy all three conditions are then filtered through their classifier, if one is defined. The classifier calls `ollama run` with a yes/no prompt. A "no" response discards the policy.

Surviving policies are grouped by type. Execution follows fixed priority:

1. **Gates** — the first matching gate denies the action. Evaluation terminates.
2. **Transforms** — all matching transforms are accumulated. Context files are merged and deduplicated. Prompts are numbered and concatenated. One `claude -p` call executes the combined transformation. The rewritten value replaces the original tool input field.
3. **Injects** — all matching injects are accumulated. Context files are merged, read, wrapped in `<filename>` tags, and returned as additional context.

If nothing matches, hooker exits silently with code 0.

Every error path fails open. Invalid JSON, missing policies file, malformed regex, unreachable `claude` CLI, unreachable `ollama` — all result in allowing the action. This is deliberate. hooker is a policy layer, not a security boundary.

## Policy Schema

Policies are defined in `.claude/policies.yaml` under a top-level `policies` key. Each policy is a hash.

### Required Fields

**`name`** — Human-readable label. Appears in log messages and as the default denial reason.

**`event`** — Which hook event triggers this policy:
- `PreToolUse` — fires before a tool call (Bash, Edit, Write, Read, etc.)
- `UserPromptSubmit` — fires when the user submits a prompt

**`type`** — The action to take when the policy matches:
- `gate` — deny the action
- `transform` — rewrite the action via `claude -p`
- `inject` — surface additional context to the agent

### Matching Fields

All matching fields are optional. Omitting a field means it matches everything. Multiple fields are AND-ed.

**`tool`** — Anchored regex matched against the tool name. Only meaningful for `PreToolUse` events. Examples: `Bash`, `Edit|Write`, `Read`.

**`match`** — Unanchored regex matched against the resolved content field, or a predefined **match constant**. For `PreToolUse` events, the content field is determined by `match_field`. For `UserPromptSubmit` events, it matches against the prompt text.

Match constants start with `:` and expand to patterns that handle tool-generated command variations (like `git -C /path commit` instead of `git commit`). Available constants:

| Constant | Matches |
|----------|---------|
| `:git_commit` | `git commit`, `git -C /path commit`, `git -c key=val commit` |
| `:git_push` | `git push`, `git -C /path push` |
| `:git_push_force` | `--force`, `-f`, `--force-with-lease`, and `+refspec` variants |
| `:git_reset` | `git reset`, `git -C /path reset` |
| `:git_rebase` | `git rebase`, `git -C /path rebase` |
| `:git_checkout` | `git checkout`, `git -C /path checkout` |
| `:git_switch` | `git switch`, `git -C /path switch` |
| `:git_merge` | `git merge`, `git -C /path merge` |
| `:git_stash` | `git stash`, `git -C /path stash` |
| `:git_restore` | `git restore`, `git -C /path restore` |

All constants handle global git options between `git` and the subcommand (`-C <path>`, `-c <key=value>`, `--git-dir`, relative paths). Constants are adversarially tested to reject false positives — `:git_reset` does not match `git commit -m "reset things"`, and `:git_push_force` catches `git push -f`, `git push origin +main`, and `--force-with-lease`. Unknown constants fail open with a stderr warning.

**`match_field`** — Which field of `tool_input` to match against. Only meaningful for `PreToolUse` events. Each tool has a default:

| Tool | Default `match_field` |
|------|-----------------------|
| `Bash` | `command` |
| `Edit` | `file_path` |
| `MultiEdit` | `file_path` |
| `Write` | `file_path` |
| `Read` | `file_path` |
| `Glob` | `pattern` |
| `Grep` | `pattern` |
| `NotebookEdit` | `notebook_path` |
| `Task` | `prompt` |
| `WebFetch` | `url` |
| `WebSearch` | `query` |

If the tool is not in this table and no `match_field` is specified, the fallback is `command`. If the resolved field is absent from `tool_input`, the entire `tool_input` JSON is matched instead.

### Gate Fields

**`message`** — The denial reason returned to Claude Code. If omitted, defaults to `"Blocked by policy: <name>"`.

### Transform Fields

**`transform_field`** — Which field of `tool_input` to write the transformed result into. Defaults to `match_field` (or the tool's default match field). Use this when the field you match against differs from the field you want to rewrite. Example: match on `file_path` to detect `README.md`, but set `transform_field: content` to rewrite the file content rather than the path.

**`context`** — List of file paths (relative to project root) to read and include in the transform prompt. Files are wrapped in `<filename>` tags. Multiple transforms that match the same event have their context files merged and deduplicated.

**`prompt`** — The instruction sent to the model. Describes the transformation to perform on the tool input. Multiple matching transforms have their prompts numbered and concatenated into a single `claude -p` call.

**`model`** — Model for the `claude -p` call. Passed as `--model <value>`. If omitted, uses the `claude` CLI default.

### Inject Fields

**`context`** — List of file paths (relative to project root) to read and return as additional context. Files are wrapped in `<filename>` tags. Multiple matching injects have their context files merged and deduplicated.

### Classifier (Optional, Any Policy Type)

Any policy can include a `classifier` field to gate it behind a local LLM call via ollama. The classifier runs after regex matching and before execution.

**`classifier.model`** — The ollama model to use. Default: `gemma3:1b`.

**`classifier.prompt`** — A yes/no question. If the model's response starts with "yes" (case-insensitive), the policy fires. Otherwise it is discarded. Default: `"Does this warrant review? Answer only yes or no."`

If ollama is unreachable or the call fails, the classifier returns false. The policy does not fire.

### Input JSON

hooker reads a single JSON object from stdin. Format depends on the event type.

**PreToolUse:**

```json
{
  "hook_event_name": "PreToolUse",
  "tool_name": "Bash",
  "tool_input": {
    "command": "git push --force origin main"
  },
  "cwd": "/path/to/project"
}
```

**UserPromptSubmit:**

```json
{
  "hook_event_name": "UserPromptSubmit",
  "prompt": "redesign the authentication system",
  "cwd": "/path/to/project"
}
```

### Output JSON

hooker writes one of three JSON responses to stdout, or produces no output (silent allow).

**Gate deny:**

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "Force push is not allowed."
  }
}
```

**Transform (updated input):**

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "updatedInput": {
      "command": "git commit -m \"the rewritten message\""
    }
  }
}
```

**Inject (additional context):**

```json
{
  "hookSpecificOutput": {
    "hookEventName": "UserPromptSubmit",
    "additionalContext": "<REVIEW_PANEL.md>\n...\n</REVIEW_PANEL.md>"
  }
}
```

**Allow:** exit code 0, no stdout.

## Requirements

Ruby. Standard library only. No gems.

Transforms invoke `claude -p` — authentication is inherited from the active Claude Code session. Classifiers invoke `ollama run` — required only when policies define a classifier field.

## Testing

Two test suites. Ruby stdlib only — no gems, no test frameworks.

**Smoke tests** — deterministic, no external dependencies. Gates, injects, event filtering, tool regex matching, every fail-open path.

```bash
ruby test/test_smoke.rb
```

**End-to-end tests** — transforms and classifiers tested via PATH-shimmed binaries (no real `claude` or `ollama` needed). Live integration tests create real git repos and exercise the full pipeline with real `claude -p` and `ollama` calls. Live tests are opt-in.

```bash
ruby test/test_e2e.rb                        # shimmed only
HOOKER_E2E_LIVE=1 ruby test/test_e2e.rb      # include live integration tests
```

Live tests require `claude` CLI and `ollama` with `gemma3:1b` installed.

## Principle

If a rule can be forgotten, it will be. If a rule is structural, it cannot be.

Architecture supersedes intention. hooker makes rules structural — not suggested, not requested, not optional. Structural.
