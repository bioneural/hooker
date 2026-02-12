<h1 align="center">
  h o o k e r
  <br>
  <sub>declarative policy enforcement for claude code hooks</sub>
</h1>

Agents do not possess discipline. They possess prompts. Prompts degrade — silently, inevitably, without detection. hooker eliminates the prompt layer as an enforcement surface. What cannot be bypassed cannot be forgotten.

## The Problem

You write a rule in CLAUDE.md: "never force push to main." The agent obeys for a while. Then it forgets. Then you remind it. Then it forgets again. The failure mode is silent — no error, no warning. Gradual drift from intent.

Prompts are suggestions. hooker makes rules structural.

## What It Does

hooker sits between Claude Code and its tool calls. Every tool invocation passes through hooker before execution. Policies chain in order — a gate halts the chain, but transforms and injects both fire on the same event.

Three policy types:

- **Gate** — blocks actions that match a pattern. The first matching gate terminates evaluation.
- **Transform** — rewrites the action via a side-channel `claude -p` call. The rewrite occurs outside the main agent's context window — the agent sees the result, never the logic. Zero token pollution.
- **Inject** — surfaces context before the agent reasons. The information is present because the system placed it there, not because the agent chose to retrieve it.

Any policy can include a **`when_prompt`** condition — a plain-language LLM classifier via ollama. The classifier evaluates whether the policy should fire. It runs after pattern matching, before execution. Local inference. No remote API cost.

## What It Does Not Do

hooker is a policy layer, not a security boundary. Every error path fails open — the action is permitted, a diagnostic is logged to stderr, and the warning is surfaced to the agent through `additionalContext` in `<hooker-warnings>` tags. If hooker cannot determine the correct action, it permits the action and tells you why — in the session, not just in a log. A broken policy engine must not become a denial-of-service on the agent it governs.

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

Define policies in `.claude/policies.rb` at your project root:

```ruby
policy "No force push" do
  on :PreToolUse, tool: "Bash", match: :git_push_force
  gate "Force push is not allowed."
end
```

That is a complete, working policy. Force pushes are now structurally denied. The `:git_push_force` constant handles command variations the agent may generate (like `git -C /path push --force`) — no regex knowledge required.

### Policy Scopes

hooker discovers `.claude/policies.rb` at multiple directory levels by walking up from `cwd`. Three natural scopes emerge:

- **System-wide** — `~/.claude/policies.rb` — personal rules that apply to all projects
- **Project-wide** — `<project>/.claude/policies.rb` — the most common location
- **Directory-wide** — `<project>/src/sensitive/.claude/policies.rb` — rules for a subtree

Broader scopes evaluate first. A system-wide gate fires before a project-level gate. Context files (for `inject` and `transform`) resolve relative to each policy file's root directory — a system-wide `inject "RULES.md"` reads `~/RULES.md`, a project-level one reads `<project>/RULES.md`.

A syntax error in one file skips that file and logs the error to stderr. Other levels still evaluate.

## Examples

Each example shows the policy, what hooker receives, and what it outputs.

### Gate — block an action

Policy:

```ruby
policy "No env edits" do
  on :PreToolUse, tool: "Edit|Write", file: ".env"
  gate "Modifying .env files is prohibited."
end
```

Input (from Claude Code via stdin):

```json
{
  "hook_event_name": "PreToolUse",
  "tool_name": "Write",
  "tool_input": {
    "file_path": "/app/.env",
    "content": "API_KEY=secret"
  },
  "cwd": "/app"
}
```

Output (stdout):

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "Modifying .env files is prohibited."
  }
}
```

The action is blocked. Claude Code sees the denial reason and does not execute the tool call.

### Transform — rewrite an action

Policy:

```ruby
policy "Conventional commits" do
  on :PreToolUse, tool: "Bash", match: :git_commit
  transform context: "COMMIT_STYLE.md",
    prompt: "Rewrite this commit message to follow the conventions in " \
            "COMMIT_STYLE.md. Preserve technical content. Return only " \
            "the complete git commit command."
end
```

Input:

```json
{
  "hook_event_name": "PreToolUse",
  "tool_name": "Bash",
  "tool_input": {
    "command": "git commit -m \"fix auth bug\""
  },
  "cwd": "/app"
}
```

hooker reads `COMMIT_STYLE.md` from the project root and assembles this prompt for `claude -p`:

```
<context>
<COMMIT_STYLE.md>
Use conventional commits: type(scope): description
Types: feat, fix, refactor, docs, test, chore
</COMMIT_STYLE.md>
</context>

<current_input>
{
  "command": "git commit -m \"fix auth bug\""
}
</current_input>

<instructions>
Rewrite this commit message to follow the conventions in COMMIT_STYLE.md.
Preserve technical content. Return only the complete git commit command.
</instructions>

Return ONLY the transformed value. No explanation, no markdown fencing.
```

The model responds with the rewritten command. hooker outputs:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "updatedInput": {
      "command": "git commit -m \"fix(auth): resolve authentication bug\""
    }
  }
}
```

Claude Code executes the rewritten command instead of the original. The agent never sees the transform logic — zero token pollution.

**`field:` override.** When matching on one field but rewriting another, use `field:` to specify the target:

```ruby
policy "License header" do
  on :PreToolUse, tool: "Write", file: /\.py$/
  transform context: "LICENSE_HEADER.txt",
    field: :content,
    prompt: "If this file does not already begin with the license header from " \
            "LICENSE_HEADER.txt, prepend it. Return only the file content."
end
```

This matches on `file_path` (to detect `.py` files) but writes the model's response to `content`. Without `field: :content`, the default target is the match field — `file_path` for Write — so the model's output would replace the file path instead of the file content.

### Inject — surface context

Policy:

```ruby
policy "Escalate to review panel when the prompt warrants it" do
  on :UserPromptSubmit
  when_prompt "The prompt involves architectural decisions, design tradeoffs " \
              "with multiple valid approaches, high-risk changes, or novel " \
              "problems without established patterns."
  inject "REVIEW_PANEL.md"
end
```

Input:

```json
{
  "hook_event_name": "UserPromptSubmit",
  "prompt": "We need to redesign the authentication system from scratch.",
  "cwd": "/app"
}
```

hooker sends the prompt to `ollama run gemma3:1b` with a yes/no classifier. The model responds "yes" — the condition matches. hooker reads `REVIEW_PANEL.md` and outputs:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "UserPromptSubmit",
    "additionalContext": "<REVIEW_PANEL.md>\n## Review Panel\n- Alice: security\n- Bob: architecture\n- Carol: UX\n</REVIEW_PANEL.md>"
  }
}
```

Claude Code injects this context into the agent's prompt before it reasons. The information is present because the system placed it there, not because the agent chose to retrieve it.

**`command:` injection.** Instead of reading a file, run a command and inject its stdout:

```ruby
policy "Inject git context" do
  on :UserPromptSubmit
  inject command: "git log --oneline -10"
end
```

The command runs with the policy's root directory as its working directory. The user's prompt is piped to the command's stdin.

## Architecture

hooker reads a JSON event from stdin. It parses the event, extracts `cwd`, and walks upward from that directory to the filesystem root, collecting every `.claude/policies.rb` found along the way. Files are merged broadest-first — a policy at `~/` evaluates before one at `~/project/`, which evaluates before one at `~/project/src/sensitive/`. If no policies files exist, the action is allowed. Exit.

Each policy is evaluated in declaration order. Three conditions are AND-ed:

1. **Event type** — exact match against `hook_event_name`. Optional. Omit to match all events.
2. **Tool name** — anchored regex (`\A(?:pattern)\z`) against `tool_name`. Optional. Only meaningful for `PreToolUse`.
3. **Content pattern** — unanchored regex against the resolved match field. Optional. Omit to match all content.

Omitting any condition means it matches everything. Policies that satisfy all three conditions are then filtered through their classifier, if one is defined (via `when_prompt` or raw `classifier` config). The classifier calls `ollama run` with a yes/no prompt. A "no" response discards the policy.

Surviving policies are grouped by type. Execution order:

1. **Gates** — the first matching gate denies the action. The chain halts. No transforms or injects fire.
2. **Transforms** and **injects** both fire. Transforms are accumulated into one `claude -p` call. Injects are accumulated into one context block. The output contains both `updatedInput` and `additionalContext` when both are present.

Context files (for `inject` and `transform`) resolve relative to the directory containing the `.claude/` that defines the policy. A system-wide policy's `inject "RULES.md"` reads `~/RULES.md`; a project policy's reads `<project>/RULES.md`. A syntax error in one policy file skips that file — other levels still evaluate.

If nothing matches, hooker exits silently with code 0.

Every error path fails open — but never silently. Invalid JSON, missing context files, malformed regex, invalid Ruby, unreachable `claude` CLI, unreachable `ollama` — all result in allowing the action, logging to stderr, and surfacing the warning through `additionalContext` wrapped in `<hooker-warnings>` tags. The agent sees the warning in the Claude Code session. The operator sees it in stderr. The action proceeds, but both know why the policy didn't fire. This is deliberate. hooker is a policy layer, not a security boundary.

## Policy DSL

Policies are defined in `.claude/policies.rb` using a Ruby DSL. Multiple files are discovered by walking up from `cwd`:

```
~/.claude/policies.rb              # system-wide (all projects)
<project>/.claude/policies.rb      # project-wide
<project>/sub/.claude/policies.rb  # directory-wide (subtree)
```

All files are merged broadest-first into a single policy list. Each policy is a block:

```ruby
policy "name" do
  on :event, tool: "pattern", match: /pattern/, match_field: :field
  gate "reason"         # or transform(...) or inject(...)
  when_prompt "condition"  # optional classifier
end
```

### `on(event, tool:, match:, match_field:, file:)`

Declares what the policy matches against. All parameters except `event` are optional.

**`event`** — Which hook event triggers this policy:
- `:PreToolUse` — fires before a tool call (Bash, Edit, Write, Read, etc.)
- `:UserPromptSubmit` — fires when the user submits a prompt

**`tool:`** — Anchored regex matched against the tool name. Only meaningful for `PreToolUse` events. Examples: `"Bash"`, `"Edit|Write"`, `"Read"`.

**`match:`** — Pattern matched against the resolved content field. Accepts three forms:
- **Symbol** — a match constant (e.g., `:git_commit`). Expands to a pattern handling tool-generated command variations.
- **Regexp** — a Ruby regex literal (e.g., `/README\.md/`).
- **String** — a regex string (e.g., `"push.*--force"`).

For `UserPromptSubmit` events, the match is against the prompt text.

**`match_field:`** — Which field of `tool_input` to match against. Each tool has a default:

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

If the tool is not in this table and no `match_field:` is specified, the fallback is `command`. If the resolved field is absent from `tool_input`, the entire `tool_input` JSON is matched instead.

**`file:`** — Sugar for matching against `file_path`. Sets `match_field: :file_path` automatically. Accepts two forms:
- **String** — exact filename match. The string is auto-escaped (dots are literal) and anchored to path component boundaries. `file: ".env"` matches `/app/.env` but not `/app/.environment` or `/app/X.env`.
- **Regexp** — unanchored regex against the full `file_path`. `file: /\.env/` matches `/app/.env.local`.

If `file:` is specified, `match:` and `match_field:` are ignored.

```ruby
# These are equivalent:
on :PreToolUse, tool: "Write", match: /\.env/, match_field: :file_path
on :PreToolUse, tool: "Write", file: /\.env/

# But file: with a string is an exact match (not regex):
on :PreToolUse, tool: "Write", file: ".env"     # matches .env only
on :PreToolUse, tool: "Write", file: "README.md" # matches README.md only
```

### Match Constants

Match constants start with `:` and expand to patterns that handle tool-generated command variations (like `git -C /path commit` instead of `git commit`). Use Ruby symbols in the DSL:

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

### `gate(message = nil)`

Blocks the action. Returns a deny decision to Claude Code.

**`message`** — The denial reason. If omitted, defaults to `"Blocked by policy: <name>"`.

### `transform(context:, prompt:, field:, model:)`

Rewrites the action via a side-channel `claude -p` call.

**`context:`** — File path or array of file paths (relative to the policy file's root directory) to read and include in the transform prompt. Files are wrapped in `<filename>` tags.

**`prompt:`** — The instruction sent to the model. Describes the transformation to perform.

**`field:`** — Which field of `tool_input` to write the transformed result into. Defaults to `match_field` (or the tool's default match field). Use this when the field you match against differs from the field you want to rewrite.

**`model:`** — Model for the `claude -p` call. Passed as `--model <value>`. If omitted, uses the `claude` CLI default.

**Assembled prompt.** hooker builds the prompt sent to `claude -p` from four parts, in order:

```
<context>
<COMMIT_STYLE.md>
[contents of COMMIT_STYLE.md]
</COMMIT_STYLE.md>
</context>

<current_input>
{
  "command": "git commit -m \"fix bug in auth\""
}
</current_input>

<instructions>
Rewrite this commit message to follow the conventions in COMMIT_STYLE.md.
</instructions>

Return ONLY the transformed value. No explanation, no markdown fencing.
```

- **`<context>`** — present only when `context:` files are specified. Each file is wrapped in `<filename>` tags using the basename (not the full path). Multiple files appear as siblings inside the `<context>` block.
- **`<current_input>`** — the full `tool_input` JSON from the hook event, pretty-printed. For a Bash tool call this includes `command`; for a Write call it includes `file_path` and `content`.
- **`<instructions>`** — the `prompt:` string. When multiple transforms match the same event, their prompts are numbered (`1. ...`, `2. ...`) and concatenated.
- **Trailing directive** — a fixed suffix instructing the model to return only the transformed value.

The model's response replaces the value of the target field (`field:`, or the default match field). Write your `prompt:` knowing that the model can reference context files by their `<filename>` tags and can see the full tool input JSON.

### `inject(*files, command:)`

Surfaces context to the agent before it reasons.

**`files`** — One or more file paths (relative to the policy file's root directory) to read and return as additional context. Files are wrapped in `<filename>` tags. Multiple matching injects have their context files merged and deduplicated.

**`command:`** — A shell command whose stdout becomes additional context. The command runs with the policy's root directory as its working directory. The user's prompt (or tool input command) is piped to stdin. Fails open — if the command exits non-zero or is not found, the inject is skipped.

### `when_prompt(condition, model:)`

Gates the policy behind a local LLM classifier via ollama. The condition is plain language — no regex, no code. hooker wraps it into a yes/no classifier prompt automatically.

```ruby
when_prompt "The prompt involves architectural decisions."
when_prompt "The prompt involves security concerns.", model: "llama3:8b"
```

**`condition`** — A plain-language description of when the policy should fire.

**`model:`** — The ollama model to use. Default: `gemma3:1b`.

The classifier runs after pattern matching and before execution. If the model responds with "yes" (case-insensitive), the policy fires. Otherwise it is discarded. If ollama is unreachable or the call fails, the classifier returns false — the policy does not fire.

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

hooker writes a JSON response to stdout, or produces no output (silent allow). When both transforms and injects match the same event, the output contains both fields.

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

**Transform + inject (both fire):**

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "updatedInput": {
      "command": "git commit -m \"the rewritten message\""
    },
    "additionalContext": "<REVIEW_PANEL.md>\n...\n</REVIEW_PANEL.md>"
  }
}
```

Either field may appear alone when only transforms or only injects match.

**Allow:** exit code 0, no stdout.

## Requirements

Ruby. Standard library only. No gems.

Transforms invoke `claude -p` — authentication is inherited from the active Claude Code session. Classifiers invoke `ollama run` — required only when policies use `when_prompt`.

## Testing

Two test suites. Ruby stdlib only — no gems, no test frameworks.

**Smoke tests** — deterministic, no external dependencies. Gates, injects, event filtering, tool regex matching, match constants, DSL features (Regexp literals, Symbol constants, invalid Ruby fail-open), every fail-open path.

```bash
ruby test/test_smoke.rb
```

**End-to-end tests** — transforms and classifiers tested via PATH-shimmed binaries (no real `claude` or `ollama` needed). Includes `when_prompt` tests (auto-generated classifier prompt, custom model, skip-when-absent). Live integration tests create real git repos and exercise the full pipeline with real `claude -p` and `ollama` calls. Live tests are opt-in.

```bash
ruby test/test_e2e.rb                        # shimmed only
HOOKER_E2E_LIVE=1 ruby test/test_e2e.rb      # include live integration tests
```

Live tests require `claude` CLI and `ollama` with `gemma3:1b` installed.

## Principle

If a rule can be forgotten, it will be. If a rule is structural, it cannot be.

Architecture supersedes intention. hooker makes rules structural — not suggested, not requested, not optional. Structural.
