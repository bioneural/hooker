#!/usr/bin/env ruby
# frozen_string_literal: true

# test/test_e2e.rb — end-to-end tests for the hooker policy engine
#
# Usage:
#   ruby test/test_e2e.rb                        # shimmed tests only
#   HOOKER_E2E_LIVE=1 ruby test/test_e2e.rb      # include live-dependency tests
#
# Tests transforms (via claude CLI) and classifiers (via ollama) using
# PATH-prepended shim scripts. Live tests against real binaries are
# opt-in via the HOOKER_E2E_LIVE environment variable.
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
$skip = 0

def assert(label, condition, detail = nil)
  if condition
    $pass += 1
    puts "  PASS  #{label}"
  else
    $fail += 1
    puts "  FAIL  #{label}#{detail ? " -- #{detail}" : ''}"
  end
end

def skip(label, reason)
  $skip += 1
  puts "  SKIP  #{label} (#{reason})"
end

def run_hooker(input_hash, policies_rb:, context_files: {}, env: {})
  Dir.mktmpdir('hooker-e2e') do |tmpdir|
    claude_dir = File.join(tmpdir, '.claude')
    FileUtils.mkdir_p(claude_dir)
    File.write(File.join(claude_dir, 'policies.rb'), policies_rb)

    context_files.each do |rel_path, content|
      abs = File.join(tmpdir, rel_path)
      FileUtils.mkdir_p(File.dirname(abs))
      File.write(abs, content)
    end

    input = JSON.generate(input_hash.merge('cwd' => tmpdir))

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

# -- Transform Tests (shimmed) --

def test_transform_with_shim
  puts "\ntransform: rewrite via claude shim"
  policies = <<~'RUBY'
    policy "Rewrite commits" do
      on :PreToolUse, tool: "Bash", match: "git commit"
      transform prompt: "Rewrite in persona voice."
    end
  RUBY
  input = { hook_event_name: 'PreToolUse', tool_name: 'Bash',
            tool_input: { command: 'git commit -m "fix bug"' } }

  claude_shim = <<~SH
    #!/bin/sh
    echo 'git commit -m "the machine remembers what you forget"'
  SH

  with_shims('claude' => claude_shim) do |path|
    result = run_hooker(input, policies_rb: policies, env: { 'PATH' => path })
    output = parse_output(result)

    assert 'has updatedInput', output&.dig('hookSpecificOutput', 'updatedInput').is_a?(Hash)
    assert 'command was rewritten',
      output&.dig('hookSpecificOutput', 'updatedInput', 'command')&.include?('machine remembers')
    assert 'event name present', output&.dig('hookSpecificOutput', 'hookEventName') == 'PreToolUse'
  end
end

def test_transform_with_context
  puts "\ntransform: context files included in prompt"
  policies = <<~'RUBY'
    policy "Persona commits" do
      on :PreToolUse, tool: "Bash", match: "git commit"
      transform context: "IDENTITY.md",
        prompt: "Rewrite in persona voice."
    end
  RUBY
  input = { hook_event_name: 'PreToolUse', tool_name: 'Bash',
            tool_input: { command: 'git commit -m "fix bug"' } }

  # Shim captures stdin to a file so we can verify the prompt content
  claude_shim = <<~SH
    #!/bin/sh
    PROMPT=$(cat)
    if echo "$PROMPT" | grep -q "I am Vetra"; then
      echo 'git commit -m "structural correction applied"'
    else
      echo "MISSING_CONTEXT" >&2
      echo 'git commit -m "fallback"'
    fi
  SH

  with_shims('claude' => claude_shim) do |path|
    result = run_hooker(input, policies_rb: policies,
                        env: { 'PATH' => path },
                        context_files: { 'IDENTITY.md' => 'I am Vetra.' })
    output = parse_output(result)

    assert 'context was passed to claude',
      output&.dig('hookSpecificOutput', 'updatedInput', 'command')&.include?('structural correction')
    assert 'no missing context warning', !result[:stderr].include?('MISSING_CONTEXT')
  end
end

def test_multiple_transforms_accumulated
  puts "\ntransform: multiple transforms accumulated into one call"
  policies = <<~'RUBY'
    policy "Transform A" do
      on :PreToolUse, tool: "Bash", match: "git commit"
      transform prompt: "Add emoji prefix."
    end

    policy "Transform B" do
      on :PreToolUse, tool: "Bash", match: "git commit"
      transform prompt: "Make it lowercase."
    end
  RUBY
  input = { hook_event_name: 'PreToolUse', tool_name: 'Bash',
            tool_input: { command: 'git commit -m "Fix Bug"' } }

  claude_shim = <<~SH
    #!/bin/sh
    INPUT=$(cat)
    if echo "$INPUT" | grep -q "emoji" && echo "$INPUT" | grep -q "lowercase"; then
      echo 'git commit -m "both instructions received"'
    else
      echo "SHIM_ERROR: expected both instructions" >&2
      exit 1
    fi
  SH

  with_shims('claude' => claude_shim) do |path|
    result = run_hooker(input, policies_rb: policies, env: { 'PATH' => path })
    output = parse_output(result)

    assert 'has updatedInput', output&.dig('hookSpecificOutput', 'updatedInput').is_a?(Hash)
    assert 'both instructions reached claude',
      output&.dig('hookSpecificOutput', 'updatedInput', 'command')&.include?('both instructions')
    assert 'no shim error', !result[:stderr].include?('SHIM_ERROR')
  end
end

def test_transform_write_with_transform_field
  puts "\ntransform: Write transform uses transform_field to target content"
  policies = <<~'RUBY'
    policy "README voice" do
      on :PreToolUse, tool: "Write", match: 'README\.md', match_field: :file_path
      transform context: "IDENTITY.md",
        field: :content,
        prompt: "Rewrite in persona voice."
    end
  RUBY
  input = { hook_event_name: 'PreToolUse', tool_name: 'Write',
            tool_input: { file_path: '/app/README.md', content: 'A cool project for everyone.' } }

  claude_shim = <<~SH
    #!/bin/sh
    PROMPT=$(cat)
    if echo "$PROMPT" | grep -q "I am Vetra" && echo "$PROMPT" | grep -q "cool project"; then
      echo 'A system of precise architecture.'
    else
      echo "SHIM_ERROR: missing context or input" >&2
      echo 'fallback'
    fi
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
    assert 'context and input passed to claude', !result[:stderr].include?('SHIM_ERROR')
  end
end

def test_transform_failopen_claude_missing
  puts "\ntransform: fail-open when claude not in PATH"
  policies = <<~'RUBY'
    policy "Rewrite commits" do
      on :PreToolUse, tool: "Bash", match: "git commit"
      transform prompt: "Rewrite."
    end
  RUBY
  input = { hook_event_name: 'PreToolUse', tool_name: 'Bash',
            tool_input: { command: 'git commit -m "fix"' } }

  # Minimal PATH — no claude binary available
  result = run_hooker(input, policies_rb: policies, env: { 'PATH' => '/usr/bin:/bin' })

  assert 'exit 0 (fail-open)', result[:exit_code] == 0
  assert 'no updatedInput (graceful failure)', result[:stdout].strip.empty?
end

# -- Classifier Tests (shimmed) --

def test_classifier_yes
  puts "\nclassifier: ollama returns yes, inject fires"
  policies = <<~'RUBY'
    policy "Panel review" do
      on :UserPromptSubmit
      when_prompt "The input discusses architectural decisions or system design."
      inject "REVIEW_PANEL.md"
    end
  RUBY
  input = { hook_event_name: 'UserPromptSubmit', prompt: 'redesign the auth system' }

  ollama_shim = <<~SH
    #!/bin/sh
    echo "yes"
  SH

  with_shims('ollama' => ollama_shim) do |path|
    result = run_hooker(input, policies_rb: policies,
                        env: { 'PATH' => path },
                        context_files: { 'REVIEW_PANEL.md' => 'Panel: Alice, Bob, Carol' })
    output = parse_output(result)

    assert 'inject fired', !output.nil?
    assert 'context includes panel',
      output&.dig('hookSpecificOutput', 'additionalContext')&.include?('Panel: Alice, Bob, Carol')
  end
end

def test_classifier_no
  puts "\nclassifier: ollama returns no, inject suppressed"
  policies = <<~'RUBY'
    policy "Panel review" do
      on :UserPromptSubmit
      when_prompt "The input discusses architectural decisions or system design."
      inject "REVIEW_PANEL.md"
    end
  RUBY
  input = { hook_event_name: 'UserPromptSubmit', prompt: 'fix typo' }

  ollama_shim = <<~SH
    #!/bin/sh
    echo "no"
  SH

  with_shims('ollama' => ollama_shim) do |path|
    result = run_hooker(input, policies_rb: policies,
                        env: { 'PATH' => path },
                        context_files: { 'REVIEW_PANEL.md' => 'Panel: Alice, Bob, Carol' })

    assert 'no stdout (suppressed)', result[:stdout].strip.empty?
  end
end

def test_classifier_failopen_ollama_missing
  puts "\nclassifier: fail-open when ollama not in PATH"
  policies = <<~'RUBY'
    policy "Panel review" do
      on :UserPromptSubmit
      when_prompt "The input discusses architectural decisions or system design."
      inject "REVIEW_PANEL.md"
    end
  RUBY
  input = { hook_event_name: 'UserPromptSubmit', prompt: 'redesign auth' }

  # Minimal PATH — no ollama binary available
  result = run_hooker(input, policies_rb: policies,
                      env: { 'PATH' => '/usr/bin:/bin' },
                      context_files: { 'REVIEW_PANEL.md' => 'Panel members' })

  assert 'exit 0 (fail-open)', result[:exit_code] == 0
  assert 'no output (classifier failed, policy skipped)', result[:stdout].strip.empty?
end

def test_classifier_on_gate
  puts "\nclassifier: gate with when_prompt yes still denies"
  policies = <<~'RUBY'
    policy "Smart gate" do
      on :PreToolUse, tool: "Bash", match: "deploy"
      when_prompt "The input is a production deploy."
      gate "Deploy blocked by classifier."
    end
  RUBY
  input = { hook_event_name: 'PreToolUse', tool_name: 'Bash',
            tool_input: { command: 'deploy --production' } }

  ollama_shim = <<~SH
    #!/bin/sh
    echo "yes"
  SH

  with_shims('ollama' => ollama_shim) do |path|
    result = run_hooker(input, policies_rb: policies, env: { 'PATH' => path })
    output = parse_output(result)

    assert 'gate fires with classifier yes',
      output&.dig('hookSpecificOutput', 'permissionDecision') == 'deny'
  end
end

# -- when_prompt Tests (shimmed) --

def test_when_prompt_generates_classifier_prompt
  puts "\nwhen_prompt: auto-generates classifier prompt with condition"
  policies = <<~'RUBY'
    policy "Architectural review" do
      on :UserPromptSubmit
      when_prompt "The prompt involves architectural decisions."
      inject "REVIEW_PANEL.md"
    end
  RUBY
  input = { hook_event_name: 'UserPromptSubmit', prompt: 'redesign the database schema' }

  # Shim captures the prompt sent to ollama and checks it contains the condition
  ollama_shim = <<~SH
    #!/bin/sh
    INPUT=$(cat)
    if echo "$INPUT" | grep -q "architectural decisions"; then
      echo "yes"
    else
      echo "no"
    fi
  SH

  with_shims('ollama' => ollama_shim) do |path|
    result = run_hooker(input, policies_rb: policies,
                        env: { 'PATH' => path },
                        context_files: { 'REVIEW_PANEL.md' => 'Panel content here' })
    output = parse_output(result)

    assert 'when_prompt condition passed to ollama',
      output&.dig('hookSpecificOutput', 'additionalContext')&.include?('Panel content here')
  end
end

def test_when_prompt_with_custom_model
  puts "\nwhen_prompt: custom model passed to ollama"
  policies = <<~'RUBY'
    policy "Custom model review" do
      on :UserPromptSubmit
      when_prompt "The prompt involves security concerns.", model: "llama3:8b"
      inject "SECURITY.md"
    end
  RUBY
  input = { hook_event_name: 'UserPromptSubmit', prompt: 'audit the auth system' }

  # Shim checks the model argument
  ollama_shim = <<~SH
    #!/bin/sh
    if [ "$2" = "llama3:8b" ]; then
      echo "yes"
    else
      echo "WRONG_MODEL: got $2" >&2
      echo "no"
    fi
  SH

  with_shims('ollama' => ollama_shim) do |path|
    result = run_hooker(input, policies_rb: policies,
                        env: { 'PATH' => path },
                        context_files: { 'SECURITY.md' => 'Security guidelines' })
    output = parse_output(result)

    assert 'custom model used', !result[:stderr].include?('WRONG_MODEL')
    assert 'inject fired with custom model',
      output&.dig('hookSpecificOutput', 'additionalContext')&.include?('Security guidelines')
  end
end

def test_when_prompt_no_fires_without_classifier
  puts "\nwhen_prompt: policy without when_prompt skips classifier"
  policies = <<~'RUBY'
    policy "Always inject" do
      on :UserPromptSubmit
      inject "PANEL.md"
    end
  RUBY
  input = { hook_event_name: 'UserPromptSubmit', prompt: 'fix typo' }

  # No ollama shim needed — classifier should be skipped entirely
  result = run_hooker(input, policies_rb: policies,
                      env: { 'PATH' => '/usr/bin:/bin' },
                      context_files: { 'PANEL.md' => 'Panel content' })
  output = parse_output(result)

  assert 'inject fires without classifier (no ollama needed)',
    output&.dig('hookSpecificOutput', 'additionalContext')&.include?('Panel content')
end

# -- Live Tests (opt-in) --
#
# These tests create real git repos, wire in hooker with real policies,
# and exercise the full pipeline including real `claude -p` and `ollama`.

HAVE_CLAUDE = system('which claude > /dev/null 2>&1')
HAVE_OLLAMA = system('which ollama > /dev/null 2>&1')
LIVE = ENV['HOOKER_E2E_LIVE']

def setup_live_repo(policies_rb:, context_files: {})
  tmpdir = Dir.mktmpdir('hooker-live')

  # Init git repo
  system('git', 'init', tmpdir, [:out, :err] => '/dev/null')
  system('git', '-C', tmpdir, 'config', 'user.email', 'test@test.com')
  system('git', '-C', tmpdir, 'config', 'user.name', 'Test')

  # Write policies
  claude_dir = File.join(tmpdir, '.claude')
  FileUtils.mkdir_p(claude_dir)
  File.write(File.join(claude_dir, 'policies.rb'), policies_rb)

  # Write context files
  context_files.each do |rel_path, content|
    abs = File.join(tmpdir, rel_path)
    FileUtils.mkdir_p(File.dirname(abs))
    File.write(abs, content)
  end

  # Make an initial commit so HEAD exists
  File.write(File.join(tmpdir, '.gitkeep'), '')
  system('git', '-C', tmpdir, 'add', '.', [:out, :err] => '/dev/null')
  system('git', '-C', tmpdir, 'commit', '-m', 'init', [:out, :err] => '/dev/null')

  tmpdir
end

def cleanup_live_repo(tmpdir)
  FileUtils.rm_rf(tmpdir) if tmpdir && tmpdir.start_with?(Dir.tmpdir)
end

def test_live_gate_deny
  puts "\nlive: gate denies force push"
  unless LIVE && HAVE_CLAUDE
    return skip('live gate deny', 'requires HOOKER_E2E_LIVE=1')
  end

  policies = <<~'RUBY'
    policy "No force push" do
      on :PreToolUse, tool: "Bash", match: "push.*--force"
      gate "Force push is not allowed."
    end
  RUBY

  tmpdir = setup_live_repo(policies_rb: policies)
  input = {
    hook_event_name: 'PreToolUse',
    tool_name: 'Bash',
    tool_input: { command: 'git push --force origin main' },
    cwd: tmpdir
  }

  stdout, stderr, status = Open3.capture3(HOOKER, stdin_data: JSON.generate(input))
  output = stdout.strip.empty? ? nil : JSON.parse(stdout)

  assert 'gate returns deny', output&.dig('hookSpecificOutput', 'permissionDecision') == 'deny'
  assert 'reason is correct', output&.dig('hookSpecificOutput', 'permissionDecisionReason') == 'Force push is not allowed.'
ensure
  cleanup_live_repo(tmpdir)
end

def test_live_gate_allow
  puts "\nlive: gate allows normal push"
  unless LIVE && HAVE_CLAUDE
    return skip('live gate allow', 'requires HOOKER_E2E_LIVE=1')
  end

  policies = <<~'RUBY'
    policy "No force push" do
      on :PreToolUse, tool: "Bash", match: "push.*--force"
      gate "Force push is not allowed."
    end
  RUBY

  tmpdir = setup_live_repo(policies_rb: policies)
  input = {
    hook_event_name: 'PreToolUse',
    tool_name: 'Bash',
    tool_input: { command: 'git push origin main' },
    cwd: tmpdir
  }

  stdout, _stderr, status = Open3.capture3(HOOKER, stdin_data: JSON.generate(input))

  assert 'normal push allowed (no output)', stdout.strip.empty?
  assert 'exit 0', status.exitstatus == 0
ensure
  cleanup_live_repo(tmpdir)
end

def test_live_transform_commit
  puts "\nlive: transform rewrites commit message via real claude -p"
  unless LIVE && HAVE_CLAUDE
    return skip('live transform', 'requires claude CLI and HOOKER_E2E_LIVE=1')
  end

  policies = <<~'RUBY'
    policy "Persona commits" do
      on :PreToolUse, tool: "Bash", match: "git commit"
      transform context: "IDENTITY.md",
        prompt: "Rewrite this commit message so it begins with the word \"structural\". " \
                "Keep the rest of the technical content. Return only the complete git commit command."
    end
  RUBY

  identity = <<~'MD'
    You are a precise, measured intelligence. Every word is deliberate.
  MD

  tmpdir = setup_live_repo(policies_rb: policies, context_files: { 'IDENTITY.md' => identity })
  input = {
    hook_event_name: 'PreToolUse',
    tool_name: 'Bash',
    tool_input: { command: 'git commit -m "add user authentication"' },
    cwd: tmpdir
  }

  stdout, stderr, status = Open3.capture3(HOOKER, stdin_data: JSON.generate(input))
  output = stdout.strip.empty? ? nil : JSON.parse(stdout)
  rewritten = output&.dig('hookSpecificOutput', 'updatedInput', 'command')

  assert 'has updatedInput', output&.dig('hookSpecificOutput', 'updatedInput').is_a?(Hash)
  assert 'command was rewritten (not original)',
    rewritten != 'git commit -m "add user authentication"'
  assert 'rewritten command contains git commit',
    rewritten&.include?('git commit')

  puts "    rewritten: #{rewritten}" if rewritten
ensure
  cleanup_live_repo(tmpdir)
end

def test_live_transform_readme
  puts "\nlive: transform rewrites README content via real claude -p"
  unless LIVE && HAVE_CLAUDE
    return skip('live transform readme', 'requires claude CLI and HOOKER_E2E_LIVE=1')
  end

  policies = <<~'RUBY'
    policy "README voice" do
      on :PreToolUse, tool: "Write", match: 'README\.md', match_field: :file_path
      transform context: "IDENTITY.md",
        field: :content,
        prompt: "Rewrite this file content so the first sentence begins with " \
                "\"This system\". Preserve all technical content. Return only the file content."
    end
  RUBY

  identity = <<~'MD'
    You are a precise, measured intelligence. Every word is deliberate.
  MD

  tmpdir = setup_live_repo(policies_rb: policies, context_files: { 'IDENTITY.md' => identity })
  original_path = "#{tmpdir}/README.md"
  input = {
    hook_event_name: 'PreToolUse',
    tool_name: 'Write',
    tool_input: { file_path: original_path, content: "A tool for managing hooks.\n\nIt works well." },
    cwd: tmpdir
  }

  stdout, stderr, status = Open3.capture3(HOOKER, stdin_data: JSON.generate(input))
  output = stdout.strip.empty? ? nil : JSON.parse(stdout)
  updated = output&.dig('hookSpecificOutput', 'updatedInput')

  assert 'has updatedInput', updated.is_a?(Hash)
  assert 'file_path preserved', updated&.dig('file_path') == original_path
  assert 'content was rewritten (not original)',
    updated&.dig('content') != "A tool for managing hooks.\n\nIt works well."
  assert 'content is a string', updated&.dig('content').is_a?(String)

  puts "    rewritten content: #{updated&.dig('content')&.lines&.first&.strip}" if updated
ensure
  cleanup_live_repo(tmpdir)
end

def test_live_env_gate
  puts "\nlive: gate blocks .env file edits"
  unless LIVE
    return skip('live env gate', 'requires HOOKER_E2E_LIVE=1')
  end

  policies = <<~'RUBY'
    policy "No env edits" do
      on :PreToolUse, tool: "Edit|Write", match: '\.env', match_field: :file_path
      gate "Modifying .env files is prohibited."
    end
  RUBY

  tmpdir = setup_live_repo(policies_rb: policies)
  input = {
    hook_event_name: 'PreToolUse',
    tool_name: 'Write',
    tool_input: { file_path: "#{tmpdir}/.env", content: 'API_KEY=secret' },
    cwd: tmpdir
  }

  stdout, _stderr, status = Open3.capture3(HOOKER, stdin_data: JSON.generate(input))
  output = stdout.strip.empty? ? nil : JSON.parse(stdout)

  assert 'gate denies .env write', output&.dig('hookSpecificOutput', 'permissionDecision') == 'deny'
  assert 'reason is correct', output&.dig('hookSpecificOutput', 'permissionDecisionReason') == 'Modifying .env files is prohibited.'
ensure
  cleanup_live_repo(tmpdir)
end

def test_live_classifier_yes
  puts "\nlive: classifier triggers inject via real ollama"
  unless LIVE && HAVE_OLLAMA
    return skip('live classifier yes', 'requires ollama and HOOKER_E2E_LIVE=1')
  end

  policies = <<~'RUBY'
    policy "Panel escalation" do
      on :UserPromptSubmit
      when_prompt "The input discusses architectural decisions or system design."
      inject "REVIEW_PANEL.md"
    end
  RUBY

  panel = <<~'MD'
    ## Review Panel
    - Dr. Marchetti: cognitive science
    - Marcus Chen: DevOps
    - Sadie Okafor: prompt engineering
  MD

  tmpdir = setup_live_repo(policies_rb: policies, context_files: { 'REVIEW_PANEL.md' => panel })
  input = {
    hook_event_name: 'UserPromptSubmit',
    prompt: 'We need to redesign the entire authentication architecture from scratch. This is a major system design decision.',
    cwd: tmpdir
  }

  stdout, stderr, status = Open3.capture3(HOOKER, stdin_data: JSON.generate(input))
  output = stdout.strip.empty? ? nil : JSON.parse(stdout)
  ctx = output&.dig('hookSpecificOutput', 'additionalContext')

  assert 'classifier triggered inject', !output.nil?
  assert 'panel context surfaced', ctx&.include?('Dr. Marchetti')
  assert 'context wrapped in tags', ctx&.include?('<REVIEW_PANEL.md>')

  puts "    classifier result: inject fired" if ctx
ensure
  cleanup_live_repo(tmpdir)
end

def test_live_classifier_no
  puts "\nlive: classifier suppresses inject via real ollama"
  unless LIVE && HAVE_OLLAMA
    return skip('live classifier no', 'requires ollama and HOOKER_E2E_LIVE=1')
  end

  policies = <<~'RUBY'
    policy "Panel escalation" do
      on :UserPromptSubmit
      when_prompt "The input discusses architectural decisions or system design."
      inject "REVIEW_PANEL.md"
    end
  RUBY

  tmpdir = setup_live_repo(policies_rb: policies,
                           context_files: { 'REVIEW_PANEL.md' => 'Panel members' })
  input = {
    hook_event_name: 'UserPromptSubmit',
    prompt: 'fix the typo on line 3',
    cwd: tmpdir
  }

  stdout, _stderr, status = Open3.capture3(HOOKER, stdin_data: JSON.generate(input))

  assert 'classifier suppressed inject (no output)', stdout.strip.empty?

  puts "    classifier result: suppressed" if stdout.strip.empty?
ensure
  cleanup_live_repo(tmpdir)
end

def test_live_no_matching_policy
  puts "\nlive: no matching policy allows action"
  unless LIVE
    return skip('live no match', 'requires HOOKER_E2E_LIVE=1')
  end

  policies = <<~'RUBY'
    policy "No force push" do
      on :PreToolUse, tool: "Bash", match: "push.*--force"
      gate "Force push is not allowed."
    end
  RUBY

  tmpdir = setup_live_repo(policies_rb: policies)
  input = {
    hook_event_name: 'PreToolUse',
    tool_name: 'Bash',
    tool_input: { command: 'ls -la' },
    cwd: tmpdir
  }

  stdout, _stderr, status = Open3.capture3(HOOKER, stdin_data: JSON.generate(input))

  assert 'no output (action allowed)', stdout.strip.empty?
  assert 'exit 0', status.exitstatus == 0
ensure
  cleanup_live_repo(tmpdir)
end

# -- Runner --

def run_tests
  puts "hooker e2e tests"
  puts '=' * 40

  # Shimmed transforms
  test_transform_with_shim
  test_transform_with_context
  test_multiple_transforms_accumulated
  test_transform_write_with_transform_field
  test_transform_failopen_claude_missing

  # Shimmed classifiers
  test_classifier_yes
  test_classifier_no
  test_classifier_failopen_ollama_missing
  test_classifier_on_gate

  # Shimmed when_prompt
  test_when_prompt_generates_classifier_prompt
  test_when_prompt_with_custom_model
  test_when_prompt_no_fires_without_classifier

  # Live (opt-in) — real git repos, real claude -p, real ollama
  test_live_gate_deny
  test_live_gate_allow
  test_live_env_gate
  test_live_no_matching_policy
  test_live_transform_commit
  test_live_transform_readme
  test_live_classifier_yes
  test_live_classifier_no

  puts '=' * 40
  puts "#{$pass} passed, #{$fail} failed, #{$skip} skipped"
  exit($fail > 0 ? 1 : 0)
end

run_tests
