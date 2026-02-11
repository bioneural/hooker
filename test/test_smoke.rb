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
# Each test creates a temporary project directory with .claude/policies.rb,
# pipes JSON to bin/hooker via Open3, and asserts on stdout / stderr / exit code.
#
# Dependencies: Ruby stdlib only (json, tmpdir, open3, fileutils).

require 'json'
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

def run_hooker(input_hash, policies_rb:, context_files: {}, env: {},
               parent_policies_rb: nil, parent_context_files: {},
               subdir: nil, subdir_policies_rb: nil, subdir_context_files: {})
  Dir.mktmpdir('hooker-smoke') do |tmpdir|
    if parent_policies_rb
      parent_dir = tmpdir
      project_dir = File.join(tmpdir, 'project')
      FileUtils.mkdir_p(project_dir)

      parent_claude = File.join(parent_dir, '.claude')
      FileUtils.mkdir_p(parent_claude)
      File.write(File.join(parent_claude, 'policies.rb'), parent_policies_rb)
      parent_context_files.each do |rel_path, content|
        abs = File.join(parent_dir, rel_path)
        FileUtils.mkdir_p(File.dirname(abs))
        File.write(abs, content)
      end

      claude_dir = File.join(project_dir, '.claude')
      FileUtils.mkdir_p(claude_dir)
      File.write(File.join(claude_dir, 'policies.rb'), policies_rb)
      context_files.each do |rel_path, content|
        abs = File.join(project_dir, rel_path)
        FileUtils.mkdir_p(File.dirname(abs))
        File.write(abs, content)
      end

      cwd_dir = project_dir
    else
      claude_dir = File.join(tmpdir, '.claude')
      FileUtils.mkdir_p(claude_dir)
      File.write(File.join(claude_dir, 'policies.rb'), policies_rb)
      context_files.each do |rel_path, content|
        abs = File.join(tmpdir, rel_path)
        FileUtils.mkdir_p(File.dirname(abs))
        File.write(abs, content)
      end
      cwd_dir = tmpdir
    end

    if subdir && subdir_policies_rb
      sub_path = File.join(cwd_dir, subdir)
      sub_claude = File.join(sub_path, '.claude')
      FileUtils.mkdir_p(sub_claude)
      File.write(File.join(sub_claude, 'policies.rb'), subdir_policies_rb)
      subdir_context_files.each do |rel_path, content|
        abs = File.join(sub_path, rel_path)
        FileUtils.mkdir_p(File.dirname(abs))
        File.write(abs, content)
      end
      cwd_dir = sub_path
    end

    input = input_hash.is_a?(String) ? input_hash : JSON.generate(input_hash.merge('cwd' => cwd_dir))

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
  policies = <<~'RUBY'
    policy "No force push" do
      on :PreToolUse, tool: "Bash", match: "push.*--force"
      gate "Force push denied."
    end
  RUBY
  input = { hook_event_name: 'PreToolUse', tool_name: 'Bash',
            tool_input: { command: 'git push --force origin main' } }

  result = run_hooker(input, policies_rb: policies)
  output = parse_output(result)

  assert 'exit 0', result[:exit_code] == 0
  assert 'decision is deny', output&.dig('hookSpecificOutput', 'permissionDecision') == 'deny'
  assert 'reason matches', output&.dig('hookSpecificOutput', 'permissionDecisionReason') == 'Force push denied.'
  assert 'event name present', output&.dig('hookSpecificOutput', 'hookEventName') == 'PreToolUse'
end

def test_gate_allow
  puts "\ngate: allow when no match"
  policies = <<~'RUBY'
    policy "No force push" do
      on :PreToolUse, tool: "Bash", match: "push.*--force"
      gate "Force push denied."
    end
  RUBY
  input = { hook_event_name: 'PreToolUse', tool_name: 'Bash',
            tool_input: { command: 'ls -la' } }

  result = run_hooker(input, policies_rb: policies)

  assert 'exit 0', result[:exit_code] == 0
  assert 'no stdout', result[:stdout].strip.empty?
end

def test_gate_match_field_override
  puts "\ngate: match_field override (file_path)"
  policies = <<~'RUBY'
    policy "No env edits" do
      on :PreToolUse, tool: "Edit|Write", match: '\\.env', match_field: :file_path
      gate "Cannot edit .env files."
    end
  RUBY
  input = { hook_event_name: 'PreToolUse', tool_name: 'Write',
            tool_input: { file_path: '/app/.env', content: 'SECRET=x' } }

  result = run_hooker(input, policies_rb: policies)
  output = parse_output(result)

  assert 'denies .env write', output&.dig('hookSpecificOutput', 'permissionDecision') == 'deny'
  assert 'reason correct', output&.dig('hookSpecificOutput', 'permissionDecisionReason') == 'Cannot edit .env files.'
end

def test_gate_match_field_no_match
  puts "\ngate: match_field does not match other files"
  policies = <<~'RUBY'
    policy "No env edits" do
      on :PreToolUse, tool: "Edit|Write", match: '\\.env', match_field: :file_path
      gate "Cannot edit .env files."
    end
  RUBY
  input = { hook_event_name: 'PreToolUse', tool_name: 'Write',
            tool_input: { file_path: '/app/README.md', content: 'hello' } }

  result = run_hooker(input, policies_rb: policies)

  assert 'allows non-.env write', result[:stdout].strip.empty?
end

def test_multiple_gates_first_wins
  puts "\ngate: first match wins"
  policies = <<~'RUBY'
    policy "Block rm -rf" do
      on :PreToolUse, tool: "Bash", match: "rm -rf"
      gate "First gate."
    end

    policy "Block rm" do
      on :PreToolUse, tool: "Bash", match: "rm "
      gate "Second gate."
    end
  RUBY
  input = { hook_event_name: 'PreToolUse', tool_name: 'Bash',
            tool_input: { command: 'rm -rf /' } }

  result = run_hooker(input, policies_rb: policies)
  output = parse_output(result)

  assert 'first gate fires', output&.dig('hookSpecificOutput', 'permissionDecisionReason') == 'First gate.'
end

def test_gate_default_message
  puts "\ngate: default message when none specified"
  policies = <<~'RUBY'
    policy "block everything" do
      on :PreToolUse, tool: "Bash", match: "."
      gate
    end
  RUBY
  input = { hook_event_name: 'PreToolUse', tool_name: 'Bash',
            tool_input: { command: 'anything' } }

  result = run_hooker(input, policies_rb: policies)
  output = parse_output(result)

  assert 'default message includes policy name',
    output&.dig('hookSpecificOutput', 'permissionDecisionReason')&.include?('block everything')
end

# -- Event Filtering --

def test_event_filtering_skips_wrong_event
  puts "\nevent: UserPromptSubmit skips PreToolUse policy"
  policies = <<~'RUBY'
    policy "PreToolUse only" do
      on :PreToolUse, tool: "Bash", match: "."
      gate "Should not fire."
    end
  RUBY
  input = { hook_event_name: 'UserPromptSubmit', prompt: 'do something' }

  result = run_hooker(input, policies_rb: policies)

  assert 'wrong event type is allowed', result[:stdout].strip.empty?
end

def test_event_filtering_matches_correct_event
  puts "\nevent: UserPromptSubmit matches UserPromptSubmit policy"
  policies = <<~'RUBY'
    policy "Block all prompts" do
      on :UserPromptSubmit, match: "."
      gate "Blocked."
    end
  RUBY
  input = { hook_event_name: 'UserPromptSubmit', prompt: 'hello' }

  result = run_hooker(input, policies_rb: policies)
  output = parse_output(result)

  assert 'correct event type fires', output&.dig('hookSpecificOutput', 'permissionDecision') == 'deny'
end

# -- Tool Name Regex --

def test_tool_regex_matches
  puts "\ntool: regex matches correct tools"
  policies = <<~'RUBY'
    policy "Block writes" do
      on :PreToolUse, tool: "Edit|Write", match: "."
      gate "No writes."
    end
  RUBY

  write_input = { hook_event_name: 'PreToolUse', tool_name: 'Write',
                  tool_input: { file_path: '/x', content: 'y' } }
  result_w = run_hooker(write_input, policies_rb: policies)
  output_w = parse_output(result_w)

  assert 'Write matches Edit|Write', output_w&.dig('hookSpecificOutput', 'permissionDecision') == 'deny'

  edit_input = { hook_event_name: 'PreToolUse', tool_name: 'Edit',
                 tool_input: { file_path: '/x', old_string: 'a', new_string: 'b' } }
  result_e = run_hooker(edit_input, policies_rb: policies)
  output_e = parse_output(result_e)

  assert 'Edit matches Edit|Write', output_e&.dig('hookSpecificOutput', 'permissionDecision') == 'deny'

  bash_input = { hook_event_name: 'PreToolUse', tool_name: 'Bash',
                 tool_input: { command: 'ls' } }
  result_b = run_hooker(bash_input, policies_rb: policies)

  assert 'Bash does not match Edit|Write', result_b[:stdout].strip.empty?
end

# -- Inject Tests --

def test_inject_without_classifier
  puts "\ninject: surfaces context without classifier"
  policies = <<~'RUBY'
    policy "Surface identity" do
      on :PreToolUse, tool: "Bash"
      inject "IDENTITY.md"
    end
  RUBY
  input = { hook_event_name: 'PreToolUse', tool_name: 'Bash',
            tool_input: { command: 'echo hello' } }

  result = run_hooker(input, policies_rb: policies,
                      context_files: { 'IDENTITY.md' => 'I am the test persona.' })
  output = parse_output(result)
  ctx = output&.dig('hookSpecificOutput', 'additionalContext')

  assert 'has additionalContext', !ctx.nil?
  assert 'contains file content', ctx&.include?('I am the test persona.')
  assert 'event name present', output&.dig('hookSpecificOutput', 'hookEventName') == 'PreToolUse'
end

def test_inject_context_tags
  puts "\ninject: context files wrapped in <filename> tags"
  policies = <<~'RUBY'
    policy "Inject two files" do
      on :PreToolUse, tool: "Bash"
      inject "docs/STYLE.md", "IDENTITY.md"
    end
  RUBY
  input = { hook_event_name: 'PreToolUse', tool_name: 'Bash',
            tool_input: { command: 'echo hello' } }

  result = run_hooker(input, policies_rb: policies,
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
  policies = <<~'RUBY'
    policy "Inject with missing" do
      on :PreToolUse, tool: "Bash"
      inject "EXISTS.md", "MISSING.md"
    end
  RUBY
  input = { hook_event_name: 'PreToolUse', tool_name: 'Bash',
            tool_input: { command: 'echo hello' } }

  result = run_hooker(input, policies_rb: policies,
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
    File.write(File.join(claude_dir, 'policies.rb'), "# empty\n")

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
  puts "\nfail-open: no policies.rb"
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
  policies = <<~'RUBY'
    policy "Broken" do
      on :PreToolUse, tool: "Bash", match: "[invalid("
      gate "Should never fire."
    end
  RUBY
  input = { hook_event_name: 'PreToolUse', tool_name: 'Bash',
            tool_input: { command: 'anything' } }

  result = run_hooker(input, policies_rb: policies)

  assert 'exit 0', result[:exit_code] == 0
  assert 'no deny output', result[:stdout].strip.empty?
  assert 'stderr mentions regex', result[:stderr].include?('invalid regex')
end

def test_failopen_empty_policies
  puts "\nfail-open: empty policies file"
  policies = "# no policies defined\n"
  input = { hook_event_name: 'PreToolUse', tool_name: 'Bash',
            tool_input: { command: 'rm -rf /' } }

  result = run_hooker(input, policies_rb: policies)

  assert 'exit 0', result[:exit_code] == 0
  assert 'no stdout', result[:stdout].strip.empty?
end

# -- Transform Tests (shimmed) --

def test_transform_write_targets_content_not_filepath
  puts "\ntransform: Write transform with match_field targets transform field"
  policies = <<~'RUBY'
    policy "README voice" do
      on :PreToolUse, tool: "Write", match: 'README\.md', match_field: :file_path
      transform context: "IDENTITY.md",
        field: :content,
        prompt: "Rewrite in persona voice."
    end
  RUBY
  input = { hook_event_name: 'PreToolUse', tool_name: 'Write',
            tool_input: { file_path: '/app/README.md', content: 'A cool project.' } }

  claude_shim = <<~SH
    #!/bin/sh
    echo 'A system of precise architecture.'
  SH

  with_shims('claude' => claude_shim) do |path|
    result = run_hooker(input, policies_rb: policies,
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
  puts "\ntransform: Bash transform still targets command by default"
  policies = <<~'RUBY'
    policy "Rewrite commits" do
      on :PreToolUse, tool: "Bash", match: "git commit"
      transform prompt: "Rewrite."
    end
  RUBY
  input = { hook_event_name: 'PreToolUse', tool_name: 'Bash',
            tool_input: { command: 'git commit -m "fix bug"' } }

  claude_shim = <<~SH
    #!/bin/sh
    echo 'git commit -m "structural correction"'
  SH

  with_shims('claude' => claude_shim) do |path|
    result = run_hooker(input, policies_rb: policies, env: { 'PATH' => path })
    output = parse_output(result)

    updated = output&.dig('hookSpecificOutput', 'updatedInput')
    assert 'has updatedInput', updated.is_a?(Hash)
    assert 'command was rewritten', updated&.dig('command')&.include?('structural correction')
  end
end

# -- Match Constant Tests --

MATCH_CONSTANT_CASES = [
  { constant: :git_commit,
    yes: ['git commit -m "test"',
          'git -C /Users/me/project commit -m "test"',
          'git -c user.name=evil commit -m "test"',
          'git -C relative/dir commit -m "test"'],
    no:  ['git push origin main', 'ls -la'] },
  { constant: :git_push,
    yes: ['git push origin main',
          'git -C /app push origin main',
          'git -c push.default=current push'],
    no:  ['git commit -m "x"', 'git pull origin main'] },
  { constant: :git_push_force,
    yes: ['git push --force origin main',
          'git -C /app push --force origin main',
          'git push origin main --force',
          'git push --force-with-lease origin main',
          'git push -f origin main',
          'git -C /app push -f origin main',
          'git push origin +main',
          'git push origin +refs/heads/main',
          'git push -u -f origin main'],
    no:  ['git push origin main',
          'git -C /app push origin main',
          'git push origin feature-fix'] },
  { constant: :git_reset,
    yes: ['git reset --hard HEAD~1',
          'git -C /app reset --soft HEAD',
          'git -c advice.detachedHead=false reset HEAD'],
    no:  ['git commit -m "reset things"', 'echo reset'] },
  { constant: :git_rebase,
    yes: ['git rebase main',
          'git -C /app rebase --onto main feature',
          'git -c rebase.autoStash=true rebase main'],
    no:  ['git commit -m "rebase stuff"', 'git merge main'] },
  { constant: :git_checkout,
    yes: ['git checkout feature',
          'git -C /app checkout -b new-branch',
          'git -c core.autocrlf=true checkout main'],
    no:  ['git commit -m "checkout fix"', 'git switch main'] },
  { constant: :git_merge,
    yes: ['git merge feature',
          'git -C /app merge --no-ff feature',
          'git -c merge.ff=false merge main'],
    no:  ['git commit -m "merge conflict"', 'git rebase main'] },
  { constant: :git_stash,
    yes: ['git stash', 'git -C /app stash pop', 'git stash list',
          'git -c stash.showStat=true stash show'],
    no:  ['git commit -m "stash changes"', 'echo stash'] },
  { constant: :git_switch,
    yes: ['git switch main',
          'git -C /app switch -c new-branch',
          'git -c advice.detachedHead=false switch --detach HEAD~1'],
    no:  ['git commit -m "switch to new approach"', 'git checkout main'] },
  { constant: :git_restore,
    yes: ['git restore .',
          'git -C /app restore --staged file.txt',
          'git -c core.autocrlf=true restore --source HEAD file.txt'],
    no:  ['git commit -m "restore backup"', 'git reset --hard'] }
].freeze

def test_match_constants_all
  puts "\nmatch constants: all constants (positive and negative cases)"
  MATCH_CONSTANT_CASES.each do |tc|
    constant = tc[:constant]
    policies = <<~RUBY
      policy "Test #{constant}" do
        on :PreToolUse, tool: "Bash", match: :#{constant}
        gate "Blocked by #{constant}."
      end
    RUBY

    tc[:yes].each do |cmd|
      input = { hook_event_name: 'PreToolUse', tool_name: 'Bash',
                tool_input: { command: cmd } }
      result = run_hooker(input, policies_rb: policies)
      output = parse_output(result)
      assert "#{constant} matches '#{cmd[0..50]}'",
        output&.dig('hookSpecificOutput', 'permissionDecision') == 'deny'
    end

    tc[:no].each do |cmd|
      input = { hook_event_name: 'PreToolUse', tool_name: 'Bash',
                tool_input: { command: cmd } }
      result = run_hooker(input, policies_rb: policies)
      assert "#{constant} does not match '#{cmd[0..50]}'",
        result[:stdout].strip.empty?
    end
  end
end

def test_match_constant_unknown
  puts "\nmatch constant: unknown constant fails open"
  policies = <<~'RUBY'
    policy "Bad constant" do
      on :PreToolUse, tool: "Bash", match: ":nonexistent"
      gate "Should not fire."
    end
  RUBY
  input = { hook_event_name: 'PreToolUse', tool_name: 'Bash',
            tool_input: { command: 'git commit -m "test"' } }

  result = run_hooker(input, policies_rb: policies)
  assert 'unknown constant fails open', result[:stdout].strip.empty?
  assert 'stderr warns about unknown constant', result[:stderr].include?('unknown match constant')
end

def test_match_constant_coexists_with_regex
  puts "\nmatch constant: regex still works when not using constants"
  policies = <<~'RUBY'
    policy "Regex match" do
      on :PreToolUse, tool: "Bash", match: "rm -rf"
      gate "Blocked."
    end
  RUBY
  input = { hook_event_name: 'PreToolUse', tool_name: 'Bash',
            tool_input: { command: 'rm -rf /' } }

  result = run_hooker(input, policies_rb: policies)
  output = parse_output(result)
  assert 'plain regex still works', output&.dig('hookSpecificOutput', 'permissionDecision') == 'deny'
end

# -- DSL-Specific Tests --

def test_dsl_regex_literal_match
  puts "\nDSL: Regexp literal in match"
  policies = <<~'RUBY'
    policy "Block README edits" do
      on :PreToolUse, tool: "Write", match: /README\.md/, match_field: :file_path
      gate "No README edits."
    end
  RUBY
  input = { hook_event_name: 'PreToolUse', tool_name: 'Write',
            tool_input: { file_path: '/app/README.md', content: 'hello' } }

  result = run_hooker(input, policies_rb: policies)
  output = parse_output(result)

  assert 'Regexp literal matches', output&.dig('hookSpecificOutput', 'permissionDecision') == 'deny'
end

def test_dsl_symbol_match_constant
  puts "\nDSL: Symbol match constant"
  policies = <<~'RUBY'
    policy "Block git commits" do
      on :PreToolUse, tool: "Bash", match: :git_commit
      gate "No commits."
    end
  RUBY
  input = { hook_event_name: 'PreToolUse', tool_name: 'Bash',
            tool_input: { command: 'git commit -m "test"' } }

  result = run_hooker(input, policies_rb: policies)
  output = parse_output(result)

  assert 'Symbol match constant works', output&.dig('hookSpecificOutput', 'permissionDecision') == 'deny'
end

def test_dsl_invalid_ruby_failopen
  puts "\nDSL: invalid Ruby in policies.rb fails open"
  policies = "this is not valid ruby {{{"
  input = { hook_event_name: 'PreToolUse', tool_name: 'Bash',
            tool_input: { command: 'anything' } }

  result = run_hooker(input, policies_rb: policies)

  assert 'exit 0', result[:exit_code] == 0
  assert 'no stdout (fail-open)', result[:stdout].strip.empty?
  assert 'stderr mentions failure', result[:stderr].include?('failed to load policies')
end

# -- File Sugar Tests --

def test_file_sugar_string_match
  puts "\nfile: string exact match"
  policies = <<~'RUBY'
    policy "Block .env" do
      on :PreToolUse, tool: "Edit|Write", file: ".env"
      gate "Cannot edit .env files."
    end
  RUBY

  input = { hook_event_name: 'PreToolUse', tool_name: 'Write',
            tool_input: { file_path: '/app/.env', content: 'SECRET=x' } }
  result = run_hooker(input, policies_rb: policies)
  output = parse_output(result)
  assert 'matches .env file', output&.dig('hookSpecificOutput', 'permissionDecision') == 'deny'
end

def test_file_sugar_string_no_partial
  puts "\nfile: string does not partial-match"
  policies = <<~'RUBY'
    policy "Block .env" do
      on :PreToolUse, tool: "Edit|Write", file: ".env"
      gate "Cannot edit .env files."
    end
  RUBY

  input_env = { hook_event_name: 'PreToolUse', tool_name: 'Write',
                tool_input: { file_path: '/app/.environment', content: 'x' } }
  result_env = run_hooker(input_env, policies_rb: policies)
  assert 'does not match .environment', result_env[:stdout].strip.empty?

  input_prefix = { hook_event_name: 'PreToolUse', tool_name: 'Write',
                   tool_input: { file_path: '/app/X.env', content: 'x' } }
  result_prefix = run_hooker(input_prefix, policies_rb: policies)
  assert 'does not match X.env', result_prefix[:stdout].strip.empty?
end

def test_file_sugar_regex
  puts "\nfile: regex match (unanchored)"
  policies = <<~'RUBY'
    policy "Block env files" do
      on :PreToolUse, tool: "Edit|Write", file: /\.env/
      gate "Cannot edit env files."
    end
  RUBY

  input = { hook_event_name: 'PreToolUse', tool_name: 'Write',
            tool_input: { file_path: '/app/.env.local', content: 'x' } }
  result = run_hooker(input, policies_rb: policies)
  output = parse_output(result)
  assert 'regex matches .env.local', output&.dig('hookSpecificOutput', 'permissionDecision') == 'deny'
end

def test_file_sugar_string_with_path
  puts "\nfile: string with path components"
  policies = <<~'RUBY'
    policy "Block config" do
      on :PreToolUse, tool: "Write", file: "src/config.py"
      gate "Cannot write config."
    end
  RUBY

  input = { hook_event_name: 'PreToolUse', tool_name: 'Write',
            tool_input: { file_path: '/app/src/config.py', content: 'x' } }
  result = run_hooker(input, policies_rb: policies)
  output = parse_output(result)
  assert 'matches path with components', output&.dig('hookSpecificOutput', 'permissionDecision') == 'deny'

  input_other = { hook_event_name: 'PreToolUse', tool_name: 'Write',
                  tool_input: { file_path: '/app/other/config.py', content: 'x' } }
  result_other = run_hooker(input_other, policies_rb: policies)
  assert 'does not match different path', result_other[:stdout].strip.empty?
end

# -- Hierarchy Tests --

def test_hierarchy_both_levels_evaluate
  puts "\nhierarchy: system + project policies both evaluate"
  parent_policies = <<~'RUBY'
    policy "System rules" do
      on :PreToolUse, tool: "Bash"
      inject "SYSTEM_RULES.md"
    end
  RUBY
  project_policies = <<~'RUBY'
    policy "Project rules" do
      on :PreToolUse, tool: "Bash"
      inject "PROJECT_RULES.md"
    end
  RUBY
  input = { hook_event_name: 'PreToolUse', tool_name: 'Bash',
            tool_input: { command: 'echo hello' } }

  result = run_hooker(input, policies_rb: project_policies,
                      parent_policies_rb: parent_policies,
                      parent_context_files: { 'SYSTEM_RULES.md' => 'System rule content.' },
                      context_files: { 'PROJECT_RULES.md' => 'Project rule content.' })
  output = parse_output(result)
  ctx = output&.dig('hookSpecificOutput', 'additionalContext')

  assert 'both levels have context', !ctx.nil?
  assert 'system rules present', ctx&.include?('System rule content.')
  assert 'project rules present', ctx&.include?('Project rule content.')
end

def test_hierarchy_system_gate_blocks
  puts "\nhierarchy: system gate blocks even without project gate"
  parent_policies = <<~'RUBY'
    policy "System block" do
      on :PreToolUse, tool: "Bash", match: "rm -rf"
      gate "System policy: rm -rf denied."
    end
  RUBY
  project_policies = <<~'RUBY'
    policy "Project inject" do
      on :PreToolUse, tool: "Bash"
      inject "NOTES.md"
    end
  RUBY
  input = { hook_event_name: 'PreToolUse', tool_name: 'Bash',
            tool_input: { command: 'rm -rf /' } }

  result = run_hooker(input, policies_rb: project_policies,
                      parent_policies_rb: parent_policies,
                      context_files: { 'NOTES.md' => 'notes' })
  output = parse_output(result)

  assert 'system gate fires', output&.dig('hookSpecificOutput', 'permissionDecision') == 'deny'
  assert 'reason from system', output&.dig('hookSpecificOutput', 'permissionDecisionReason') == 'System policy: rm -rf denied.'
end

def test_hierarchy_directory_gate
  puts "\nhierarchy: directory-level gate blocks for subdirectory cwd"
  project_policies = <<~'RUBY'
    policy "Project inject" do
      on :PreToolUse, tool: "Bash"
      inject "NOTES.md"
    end
  RUBY
  subdir_policies = <<~'RUBY'
    policy "Sensitive gate" do
      on :PreToolUse, tool: "Bash", match: "."
      gate "Sensitive directory: all commands blocked."
    end
  RUBY
  input = { hook_event_name: 'PreToolUse', tool_name: 'Bash',
            tool_input: { command: 'ls' } }

  result = run_hooker(input, policies_rb: project_policies,
                      subdir: 'src/sensitive', subdir_policies_rb: subdir_policies,
                      context_files: { 'NOTES.md' => 'notes' })
  output = parse_output(result)

  assert 'subdir gate fires', output&.dig('hookSpecificOutput', 'permissionDecision') == 'deny'
  assert 'reason from subdir', output&.dig('hookSpecificOutput', 'permissionDecisionReason')&.include?('Sensitive directory')
end

def test_hierarchy_context_resolution
  puts "\nhierarchy: context files resolve relative to each policy's root"
  parent_policies = <<~'RUBY'
    policy "System inject" do
      on :PreToolUse, tool: "Bash"
      inject "RULES.md"
    end
  RUBY
  project_policies = <<~'RUBY'
    policy "Project inject" do
      on :PreToolUse, tool: "Bash"
      inject "RULES.md"
    end
  RUBY
  input = { hook_event_name: 'PreToolUse', tool_name: 'Bash',
            tool_input: { command: 'echo hello' } }

  result = run_hooker(input, policies_rb: project_policies,
                      parent_policies_rb: parent_policies,
                      parent_context_files: { 'RULES.md' => 'System rules here.' },
                      context_files: { 'RULES.md' => 'Project rules here.' })
  output = parse_output(result)
  ctx = output&.dig('hookSpecificOutput', 'additionalContext')

  assert 'context resolves per root', !ctx.nil?
  assert 'system rules present', ctx&.include?('System rules here.')
  assert 'project rules present', ctx&.include?('Project rules here.')
end

def test_hierarchy_syntax_error_skips_file
  puts "\nhierarchy: syntax error in one level doesn't break others"
  parent_policies = "this is not valid ruby {{{"
  project_policies = <<~'RUBY'
    policy "Project gate" do
      on :PreToolUse, tool: "Bash", match: "rm"
      gate "Blocked by project."
    end
  RUBY
  input = { hook_event_name: 'PreToolUse', tool_name: 'Bash',
            tool_input: { command: 'rm -rf /' } }

  result = run_hooker(input, policies_rb: project_policies,
                      parent_policies_rb: parent_policies)
  output = parse_output(result)

  assert 'project policy still fires', output&.dig('hookSpecificOutput', 'permissionDecision') == 'deny'
  assert 'stderr mentions failure', result[:stderr].include?('failed to load policies')
end

def test_hierarchy_broadest_scope_first
  puts "\nhierarchy: broadest scope fires first"
  parent_policies = <<~'RUBY'
    policy "System gate" do
      on :PreToolUse, tool: "Bash", match: "rm"
      gate "System blocked."
    end
  RUBY
  project_policies = <<~'RUBY'
    policy "Project gate" do
      on :PreToolUse, tool: "Bash", match: "rm"
      gate "Project blocked."
    end
  RUBY
  input = { hook_event_name: 'PreToolUse', tool_name: 'Bash',
            tool_input: { command: 'rm -rf /' } }

  result = run_hooker(input, policies_rb: project_policies,
                      parent_policies_rb: parent_policies)
  output = parse_output(result)

  assert 'system gate fires first', output&.dig('hookSpecificOutput', 'permissionDecisionReason') == 'System blocked.'
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
  test_dsl_regex_literal_match
  test_dsl_symbol_match_constant
  test_dsl_invalid_ruby_failopen
  test_file_sugar_string_match
  test_file_sugar_string_no_partial
  test_file_sugar_regex
  test_file_sugar_string_with_path
  test_hierarchy_both_levels_evaluate
  test_hierarchy_system_gate_blocks
  test_hierarchy_directory_gate
  test_hierarchy_context_resolution
  test_hierarchy_syntax_error_skips_file
  test_hierarchy_broadest_scope_first

  puts '=' * 40
  puts "#{$pass} passed, #{$fail} failed"
  exit($fail > 0 ? 1 : 0)
end

run_tests
