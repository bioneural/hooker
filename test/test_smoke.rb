#!/usr/bin/env ruby
# frozen_string_literal: true

# test/test_smoke.rb — deterministic smoke tests for the hooker policy engine
#
# Usage:
#   ruby test/test_smoke.rb
#
# Tests gate, inject, matching, and fail-open behavior. No external
# dependencies — no claude CLI, no ollama. Every test is deterministic
# and runs in milliseconds.
#
# Each test creates a temporary project directory with .claude/policies.yaml,
# pipes JSON to bin/hooker via Open3, and asserts on stdout / stderr / exit code.
#
# Dependencies: Ruby stdlib only (json, yaml, tmpdir, open3, fileutils).

require 'json'
require 'yaml'
require 'tmpdir'
require 'open3'
require 'fileutils'

HOOKER = File.expand_path('../bin/hooker', __dir__)

# -- Harness --

$pass = 0
$fail = 0

def assert(label, condition, detail = nil)
  if condition
    $pass += 1
    puts "  PASS  #{label}"
  else
    $fail += 1
    puts "  FAIL  #{label}#{detail ? " -- #{detail}" : ''}"
  end
end

def run_hooker(input_hash, policies_yaml:, context_files: {}, env: {})
  Dir.mktmpdir('hooker-smoke') do |tmpdir|
    claude_dir = File.join(tmpdir, '.claude')
    FileUtils.mkdir_p(claude_dir)
    File.write(File.join(claude_dir, 'policies.yaml'), policies_yaml)

    context_files.each do |rel_path, content|
      abs = File.join(tmpdir, rel_path)
      FileUtils.mkdir_p(File.dirname(abs))
      File.write(abs, content)
    end

    input = input_hash.is_a?(String) ? input_hash : JSON.generate(input_hash.merge('cwd' => tmpdir))

    merged_env = env.transform_keys(&:to_s)
    stdout, stderr, status = Open3.capture3(merged_env, HOOKER, stdin_data: input)

    { stdout: stdout, stderr: stderr, exit_code: status.exitstatus }
  end
end

def parse_output(result)
  return nil if result[:stdout].strip.empty?
  JSON.parse(result[:stdout])
end

def with_shims(shims)
  Dir.mktmpdir('hooker-shims') do |shim_dir|
    shims.each do |name, script_body|
      path = File.join(shim_dir, name)
      File.write(path, script_body)
      File.chmod(0o755, path)
    end
    yield "#{shim_dir}:#{ENV['PATH']}"
  end
end

# -- Gate Tests --

def test_gate_deny
  puts "\ngate: deny on pattern match"
  policies = <<~'YAML'
    policies:
      - name: no force push
        event: PreToolUse
        tool: Bash
        match: "push.*--force"
        type: gate
        message: "Force push denied."
  YAML
  input = { hook_event_name: 'PreToolUse', tool_name: 'Bash',
            tool_input: { command: 'git push --force origin main' } }

  result = run_hooker(input, policies_yaml: policies)
  output = parse_output(result)

  assert 'exit 0', result[:exit_code] == 0
  assert 'decision is deny', output&.dig('hookSpecificOutput', 'permissionDecision') == 'deny'
  assert 'reason matches', output&.dig('hookSpecificOutput', 'permissionDecisionReason') == 'Force push denied.'
  assert 'event name present', output&.dig('hookSpecificOutput', 'hookEventName') == 'PreToolUse'
end

def test_gate_allow
  puts "\ngate: allow when no match"
  policies = <<~'YAML'
    policies:
      - name: no force push
        event: PreToolUse
        tool: Bash
        match: "push.*--force"
        type: gate
        message: "Force push denied."
  YAML
  input = { hook_event_name: 'PreToolUse', tool_name: 'Bash',
            tool_input: { command: 'ls -la' } }

  result = run_hooker(input, policies_yaml: policies)

  assert 'exit 0', result[:exit_code] == 0
  assert 'no stdout', result[:stdout].strip.empty?
end

def test_gate_match_field_override
  puts "\ngate: match_field override (file_path)"
  policies = <<~'YAML'
    policies:
      - name: no env edits
        event: PreToolUse
        tool: Edit|Write
        match_field: file_path
        match: "\\.env"
        type: gate
        message: "Cannot edit .env files."
  YAML
  input = { hook_event_name: 'PreToolUse', tool_name: 'Write',
            tool_input: { file_path: '/app/.env', content: 'SECRET=x' } }

  result = run_hooker(input, policies_yaml: policies)
  output = parse_output(result)

  assert 'denies .env write', output&.dig('hookSpecificOutput', 'permissionDecision') == 'deny'
  assert 'reason correct', output&.dig('hookSpecificOutput', 'permissionDecisionReason') == 'Cannot edit .env files.'
end

def test_gate_match_field_no_match
  puts "\ngate: match_field does not match other files"
  policies = <<~'YAML'
    policies:
      - name: no env edits
        event: PreToolUse
        tool: Edit|Write
        match_field: file_path
        match: "\\.env"
        type: gate
        message: "Cannot edit .env files."
  YAML
  input = { hook_event_name: 'PreToolUse', tool_name: 'Write',
            tool_input: { file_path: '/app/README.md', content: 'hello' } }

  result = run_hooker(input, policies_yaml: policies)

  assert 'allows non-.env write', result[:stdout].strip.empty?
end

def test_multiple_gates_first_wins
  puts "\ngate: first match wins"
  policies = <<~'YAML'
    policies:
      - name: block rm -rf
        event: PreToolUse
        tool: Bash
        match: "rm -rf"
        type: gate
        message: "First gate."
      - name: block rm
        event: PreToolUse
        tool: Bash
        match: "rm "
        type: gate
        message: "Second gate."
  YAML
  input = { hook_event_name: 'PreToolUse', tool_name: 'Bash',
            tool_input: { command: 'rm -rf /' } }

  result = run_hooker(input, policies_yaml: policies)
  output = parse_output(result)

  assert 'first gate fires', output&.dig('hookSpecificOutput', 'permissionDecisionReason') == 'First gate.'
end

def test_gate_default_message
  puts "\ngate: default message when none specified"
  policies = <<~'YAML'
    policies:
      - name: block everything
        event: PreToolUse
        tool: Bash
        match: "."
        type: gate
  YAML
  input = { hook_event_name: 'PreToolUse', tool_name: 'Bash',
            tool_input: { command: 'anything' } }

  result = run_hooker(input, policies_yaml: policies)
  output = parse_output(result)

  assert 'default message includes policy name',
    output&.dig('hookSpecificOutput', 'permissionDecisionReason')&.include?('block everything')
end

# -- Event Filtering --

def test_event_filtering_skips_wrong_event
  puts "\nevent: UserPromptSubmit skips PreToolUse policy"
  policies = <<~'YAML'
    policies:
      - name: pretooluse only
        event: PreToolUse
        tool: Bash
        match: "."
        type: gate
        message: "Should not fire."
  YAML
  input = { hook_event_name: 'UserPromptSubmit', prompt: 'do something' }

  result = run_hooker(input, policies_yaml: policies)

  assert 'wrong event type is allowed', result[:stdout].strip.empty?
end

def test_event_filtering_matches_correct_event
  puts "\nevent: UserPromptSubmit matches UserPromptSubmit policy"
  policies = <<~'YAML'
    policies:
      - name: block all prompts
        event: UserPromptSubmit
        match: "."
        type: gate
        message: "Blocked."
  YAML
  input = { hook_event_name: 'UserPromptSubmit', prompt: 'hello' }

  result = run_hooker(input, policies_yaml: policies)
  output = parse_output(result)

  assert 'correct event type fires', output&.dig('hookSpecificOutput', 'permissionDecision') == 'deny'
end

# -- Tool Name Regex --

def test_tool_regex_matches
  puts "\ntool: regex matches correct tools"
  policies = <<~'YAML'
    policies:
      - name: block writes
        event: PreToolUse
        tool: "Edit|Write"
        match: "."
        type: gate
        message: "No writes."
  YAML

  write_input = { hook_event_name: 'PreToolUse', tool_name: 'Write',
                  tool_input: { file_path: '/x', content: 'y' } }
  result_w = run_hooker(write_input, policies_yaml: policies)
  output_w = parse_output(result_w)

  assert 'Write matches Edit|Write', output_w&.dig('hookSpecificOutput', 'permissionDecision') == 'deny'

  edit_input = { hook_event_name: 'PreToolUse', tool_name: 'Edit',
                 tool_input: { file_path: '/x', old_string: 'a', new_string: 'b' } }
  result_e = run_hooker(edit_input, policies_yaml: policies)
  output_e = parse_output(result_e)

  assert 'Edit matches Edit|Write', output_e&.dig('hookSpecificOutput', 'permissionDecision') == 'deny'

  bash_input = { hook_event_name: 'PreToolUse', tool_name: 'Bash',
                 tool_input: { command: 'ls' } }
  result_b = run_hooker(bash_input, policies_yaml: policies)

  assert 'Bash does not match Edit|Write', result_b[:stdout].strip.empty?
end

# -- Inject Tests --

def test_inject_without_classifier
  puts "\ninject: surfaces context without classifier"
  policies = <<~'YAML'
    policies:
      - name: surface identity
        event: PreToolUse
        tool: Bash
        type: inject
        context:
          - IDENTITY.md
  YAML
  input = { hook_event_name: 'PreToolUse', tool_name: 'Bash',
            tool_input: { command: 'echo hello' } }

  result = run_hooker(input, policies_yaml: policies,
                      context_files: { 'IDENTITY.md' => 'I am the test persona.' })
  output = parse_output(result)
  ctx = output&.dig('hookSpecificOutput', 'additionalContext')

  assert 'has additionalContext', !ctx.nil?
  assert 'contains file content', ctx&.include?('I am the test persona.')
  assert 'event name present', output&.dig('hookSpecificOutput', 'hookEventName') == 'PreToolUse'
end

def test_inject_context_tags
  puts "\ninject: context files wrapped in <filename> tags"
  policies = <<~'YAML'
    policies:
      - name: inject two files
        event: PreToolUse
        tool: Bash
        type: inject
        context:
          - docs/STYLE.md
          - IDENTITY.md
  YAML
  input = { hook_event_name: 'PreToolUse', tool_name: 'Bash',
            tool_input: { command: 'echo hello' } }

  result = run_hooker(input, policies_yaml: policies,
                      context_files: {
                        'docs/STYLE.md' => 'Use active voice.',
                        'IDENTITY.md' => 'I am Vetra.'
                      })
  output = parse_output(result)
  ctx = output&.dig('hookSpecificOutput', 'additionalContext')

  assert 'STYLE.md has open tag', ctx&.include?('<STYLE.md>')
  assert 'STYLE.md has close tag', ctx&.include?('</STYLE.md>')
  assert 'IDENTITY.md has open tag', ctx&.include?('<IDENTITY.md>')
  assert 'IDENTITY.md has close tag', ctx&.include?('</IDENTITY.md>')
  assert 'uses basename not path', !ctx&.include?('<docs/STYLE.md>')
end

def test_inject_missing_context_file
  puts "\ninject: missing context file logged, others still surfaced"
  policies = <<~'YAML'
    policies:
      - name: inject with missing
        event: PreToolUse
        tool: Bash
        type: inject
        context:
          - EXISTS.md
          - MISSING.md
  YAML
  input = { hook_event_name: 'PreToolUse', tool_name: 'Bash',
            tool_input: { command: 'echo hello' } }

  result = run_hooker(input, policies_yaml: policies,
                      context_files: { 'EXISTS.md' => 'I exist.' })
  output = parse_output(result)
  ctx = output&.dig('hookSpecificOutput', 'additionalContext')

  assert 'existing file still surfaced', ctx&.include?('I exist.')
  assert 'stderr mentions missing file', result[:stderr].include?('not found')
end

# -- Fail-Open Tests --

def test_failopen_invalid_json
  puts "\nfail-open: invalid JSON input"
  Dir.mktmpdir('hooker-smoke') do |tmpdir|
    claude_dir = File.join(tmpdir, '.claude')
    FileUtils.mkdir_p(claude_dir)
    File.write(File.join(claude_dir, 'policies.yaml'), "policies: []\n")

    stdout, stderr, status = Open3.capture3(HOOKER, stdin_data: 'NOT VALID JSON {{{')

    assert 'exit 0', status.exitstatus == 0
    assert 'no stdout', stdout.strip.empty?
    assert 'stderr mentions parse error', stderr.include?('invalid JSON')
  end
end

def test_failopen_empty_stdin
  puts "\nfail-open: empty stdin"
  stdout, stderr, status = Open3.capture3(HOOKER, stdin_data: '')

  assert 'exit 0', status.exitstatus == 0
  assert 'no stdout', stdout.strip.empty?
end

def test_failopen_no_policies_file
  puts "\nfail-open: no policies.yaml"
  Dir.mktmpdir('hooker-smoke') do |tmpdir|
    input = JSON.generate({
      hook_event_name: 'PreToolUse', tool_name: 'Bash',
      tool_input: { command: 'rm -rf /' }, cwd: tmpdir
    })

    stdout, _stderr, status = Open3.capture3(HOOKER, stdin_data: input)

    assert 'exit 0', status.exitstatus == 0
    assert 'no stdout', stdout.strip.empty?
  end
end

def test_failopen_bad_regex
  puts "\nfail-open: bad regex in policy"
  policies = <<~'YAML'
    policies:
      - name: broken
        event: PreToolUse
        tool: Bash
        match: "[invalid("
        type: gate
        message: "Should never fire."
  YAML
  input = { hook_event_name: 'PreToolUse', tool_name: 'Bash',
            tool_input: { command: 'anything' } }

  result = run_hooker(input, policies_yaml: policies)

  assert 'exit 0', result[:exit_code] == 0
  assert 'no deny output', result[:stdout].strip.empty?
  assert 'stderr mentions regex', result[:stderr].include?('invalid regex')
end

def test_failopen_empty_policies
  puts "\nfail-open: empty policies array"
  policies = <<~'YAML'
    policies: []
  YAML
  input = { hook_event_name: 'PreToolUse', tool_name: 'Bash',
            tool_input: { command: 'rm -rf /' } }

  result = run_hooker(input, policies_yaml: policies)

  assert 'exit 0', result[:exit_code] == 0
  assert 'no stdout', result[:stdout].strip.empty?
end

# -- Transform Tests (shimmed) --

def test_transform_write_targets_content_not_filepath
  puts "\ntransform: Write transform with match_field=file_path writes to transform_field=content"
  policies = <<~'YAML'
    policies:
      - name: readme voice
        event: PreToolUse
        tool: Write
        match_field: file_path
        match: "README\\.md"
        type: transform
        transform_field: content
        context:
          - IDENTITY.md
        prompt: "Rewrite in persona voice."
  YAML
  input = { hook_event_name: 'PreToolUse', tool_name: 'Write',
            tool_input: { file_path: '/app/README.md', content: 'A cool project.' } }

  claude_shim = <<~SH
    #!/bin/sh
    echo 'A system of precise architecture.'
  SH

  with_shims('claude' => claude_shim) do |path|
    result = run_hooker(input, policies_yaml: policies,
                        env: { 'PATH' => path },
                        context_files: { 'IDENTITY.md' => 'I am Vetra.' })
    output = parse_output(result)

    updated = output&.dig('hookSpecificOutput', 'updatedInput')
    assert 'has updatedInput', updated.is_a?(Hash)
    assert 'content was rewritten', updated&.dig('content') == 'A system of precise architecture.'
    assert 'file_path preserved', updated&.dig('file_path') == '/app/README.md'
  end
end

def test_transform_bash_default_field_unchanged
  puts "\ntransform: Bash transform still targets command by default (backward compat)"
  policies = <<~'YAML'
    policies:
      - name: rewrite commits
        event: PreToolUse
        tool: Bash
        match: "git commit"
        type: transform
        prompt: "Rewrite."
  YAML
  input = { hook_event_name: 'PreToolUse', tool_name: 'Bash',
            tool_input: { command: 'git commit -m "fix bug"' } }

  claude_shim = <<~SH
    #!/bin/sh
    echo 'git commit -m "structural correction"'
  SH

  with_shims('claude' => claude_shim) do |path|
    result = run_hooker(input, policies_yaml: policies, env: { 'PATH' => path })
    output = parse_output(result)

    updated = output&.dig('hookSpecificOutput', 'updatedInput')
    assert 'has updatedInput', updated.is_a?(Hash)
    assert 'command was rewritten', updated&.dig('command')&.include?('structural correction')
  end
end

# -- Match Constant Tests --

# Each constant is tested with: (1) plain form, (2) git -C /path form,
# (3) a negative case that should NOT match.
MATCH_CONSTANT_CASES = [
  { constant: ':git_commit',
    yes: ['git commit -m "test"', 'git -C /Users/me/project commit -m "test"'],
    no:  ['git push origin main', 'ls -la'] },
  { constant: ':git_push',
    yes: ['git push origin main', 'git -C /app push origin main'],
    no:  ['git commit -m "x"', 'git pull origin main'] },
  { constant: ':git_push_force',
    yes: ['git push --force origin main', 'git -C /app push --force origin main',
          'git push origin main --force'],
    no:  ['git push origin main', 'git -C /app push origin main'] },
  { constant: ':git_reset',
    yes: ['git reset --hard HEAD~1', 'git -C /app reset --soft HEAD'],
    no:  ['git commit -m "reset things"', 'echo reset'] },
  { constant: ':git_rebase',
    yes: ['git rebase main', 'git -C /app rebase --onto main feature'],
    no:  ['git commit -m "rebase stuff"', 'git merge main'] },
  { constant: ':git_checkout',
    yes: ['git checkout feature', 'git -C /app checkout -b new-branch'],
    no:  ['git commit -m "checkout fix"', 'git switch main'] },
  { constant: ':git_merge',
    yes: ['git merge feature', 'git -C /app merge --no-ff feature'],
    no:  ['git commit -m "merge conflict"', 'git rebase main'] },
  { constant: ':git_stash',
    yes: ['git stash', 'git -C /app stash pop', 'git stash list'],
    no:  ['git commit -m "stash changes"', 'echo stash'] }
].freeze

def test_match_constants_all
  puts "\nmatch constants: all constants (positive and negative cases)"
  MATCH_CONSTANT_CASES.each do |tc|
    constant = tc[:constant]
    policies = <<~YAML
      policies:
        - name: test #{constant}
          event: PreToolUse
          tool: Bash
          match: "#{constant}"
          type: gate
          message: "Blocked by #{constant}."
    YAML

    tc[:yes].each do |cmd|
      input = { hook_event_name: 'PreToolUse', tool_name: 'Bash',
                tool_input: { command: cmd } }
      result = run_hooker(input, policies_yaml: policies)
      output = parse_output(result)
      assert "#{constant} matches '#{cmd[0..50]}'",
        output&.dig('hookSpecificOutput', 'permissionDecision') == 'deny'
    end

    tc[:no].each do |cmd|
      input = { hook_event_name: 'PreToolUse', tool_name: 'Bash',
                tool_input: { command: cmd } }
      result = run_hooker(input, policies_yaml: policies)
      assert "#{constant} does not match '#{cmd[0..50]}'",
        result[:stdout].strip.empty?
    end
  end
end

def test_match_constant_unknown
  puts "\nmatch constant: unknown constant fails open"
  policies = <<~'YAML'
    policies:
      - name: bad constant
        event: PreToolUse
        tool: Bash
        match: ":nonexistent"
        type: gate
        message: "Should not fire."
  YAML
  input = { hook_event_name: 'PreToolUse', tool_name: 'Bash',
            tool_input: { command: 'git commit -m "test"' } }

  result = run_hooker(input, policies_yaml: policies)
  assert 'unknown constant fails open', result[:stdout].strip.empty?
  assert 'stderr warns about unknown constant', result[:stderr].include?('unknown match constant')
end

def test_match_constant_coexists_with_regex
  puts "\nmatch constant: regex still works when not using constants"
  policies = <<~'YAML'
    policies:
      - name: regex match
        event: PreToolUse
        tool: Bash
        match: "rm -rf"
        type: gate
        message: "Blocked."
  YAML
  input = { hook_event_name: 'PreToolUse', tool_name: 'Bash',
            tool_input: { command: 'rm -rf /' } }

  result = run_hooker(input, policies_yaml: policies)
  output = parse_output(result)
  assert 'plain regex still works', output&.dig('hookSpecificOutput', 'permissionDecision') == 'deny'
end

# -- Runner --

def run_tests
  puts "hooker smoke tests"
  puts '=' * 40

  test_gate_deny
  test_gate_allow
  test_gate_match_field_override
  test_gate_match_field_no_match
  test_multiple_gates_first_wins
  test_gate_default_message
  test_event_filtering_skips_wrong_event
  test_event_filtering_matches_correct_event
  test_tool_regex_matches
  test_inject_without_classifier
  test_inject_context_tags
  test_inject_missing_context_file
  test_failopen_invalid_json
  test_failopen_empty_stdin
  test_failopen_no_policies_file
  test_failopen_bad_regex
  test_failopen_empty_policies
  test_transform_write_targets_content_not_filepath
  test_transform_bash_default_field_unchanged
  test_match_constants_all
  test_match_constant_unknown
  test_match_constant_coexists_with_regex

  puts '=' * 40
  puts "#{$pass} passed, #{$fail} failed"
  exit($fail > 0 ? 1 : 0)
end

run_tests
