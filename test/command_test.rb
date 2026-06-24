# frozen_string_literal: true

# Tests the CLI/rake command wrapper: LookoutFramework.command(name) { ... } emits a root
# console.command trace span (posted synchronously to /api/ingest/trace) so the run shows up in the
# Commands watcher. SQL inside the block becomes db.query child spans.
#
# Run: ruby packages/lookout-rails/test/command_test.rb

require "minitest/autorun"
require_relative "../lib/lookout_framework"

class CommandTest < Minitest::Test
  L = LookoutFramework

  def setup
    @prev = ENV["LOOKOUT_PERFORMANCE_ENABLED"]
    ENV["LOOKOUT_PERFORMANCE_ENABLED"] = "1"
    L.api_key = "test-key"
    L.base_uri = "https://lookout.test"
    @posts = []
    sink = method(:record)
    # finish_command_trace! posts synchronously via post_to(path, body, env_forced:).
    L.define_singleton_method(:post_to) { |path, body, env_forced: false| sink.call(path, body, env_forced) }
    Thread.current[:_lookout_trace] = nil
  end

  def teardown
    if @prev.nil?
      ENV.delete("LOOKOUT_PERFORMANCE_ENABLED")
    else
      ENV["LOOKOUT_PERFORMANCE_ENABLED"] = @prev
    end
    Thread.current[:_lookout_trace] = nil
  end

  def record(path, body, forced)
    @posts << [path, body, forced]
  end

  def test_successful_command_posts_console_command_root_span
    result = L.command("rake lookout:backup") { 42 }

    assert_equal 42, result, "command returns the block's value"
    assert_equal 1, @posts.size
    path, body, forced = @posts[0]
    assert_equal "/api/ingest/trace", path
    assert_equal "rake lookout:backup", body["transaction"]
    assert_match(/\A[0-9a-f]{32}\z/, body["trace_id"])

    root = body["spans"].first
    assert_equal "console.command", root["op"]
    assert_nil root["parent_span_id"]
    assert_equal "rake lookout:backup", root["description"]
    assert_equal "ok", root["status"]
    assert_equal 0, root["data"]["exit_code"]
    assert_operator root["end_timestamp"], :>=, root["start_timestamp"]
    assert_equal true, forced
  end

  def test_failing_command_records_error_status_and_reraises
    err = assert_raises(RuntimeError) do
      L.command("rake lookout:boom") { raise "kaboom" }
    end
    assert_equal "kaboom", err.message

    root = @posts[0][1]["spans"].first
    assert_equal "error", root["status"]
    assert_equal 1, root["data"]["exit_code"]
  end

  def test_command_is_a_passthrough_when_performance_disabled
    ENV.delete("LOOKOUT_PERFORMANCE_ENABLED")
    # Freeze remote config empty so traces_enabled? resolves false without a network call.
    L.instance_variable_set(:@remote_config, {})
    L.instance_variable_set(:@remote_config_at, Process.clock_gettime(Process::CLOCK_MONOTONIC))
    L.instance_variable_set(:@remote_config_ttl, 300)

    result = L.command("rake noop") { 7 }
    assert_equal 7, result
    assert_empty @posts, "nothing posted when the performance signal is off"
  end
end
