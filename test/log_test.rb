# frozen_string_literal: true

# Tests the log forwarder: LookoutFramework.log(level, message, attrs) buffers structured records and
# flush_logs! posts them batched to /api/ingest/log as { "entries" => [...] }, mirroring the Laravel
# log client (level normalization, source "ruby", epoch-float timestamp, attributes).
#
# Run: ruby packages/lookout-rails/test/log_test.rb

require "minitest/autorun"
require_relative "../lib/lookout_framework"

class LogTest < Minitest::Test
  L = LookoutFramework

  def setup
    @prev = ENV["LOOKOUT_LOGS_ENABLED"]
    ENV["LOOKOUT_LOGS_ENABLED"] = "1"
    L.api_key = "test-key"
    L.base_uri = "https://lookout.test"
    @posts = []
    sink = method(:record)
    L.define_singleton_method(:post_to) { |path, body, env_forced: false| sink.call(path, body, env_forced) }
    L.instance_variable_set(:@log_buffer, [])
  end

  def teardown
    if @prev.nil?
      ENV.delete("LOOKOUT_LOGS_ENABLED")
    else
      ENV["LOOKOUT_LOGS_ENABLED"] = @prev
    end
    L.instance_variable_set(:@log_buffer, [])
  end

  def record(path, body, forced)
    @posts << [path, body, forced]
  end

  def test_buffers_until_flush_then_posts_batched_entries
    L.log(:info, "first message")
    L.log("warning", "second message", { user_id: 7, payload: { a: 1 } })
    assert_empty @posts, "entries are buffered until flush"

    L.flush_logs!

    assert_equal 1, @posts.size
    path, body, forced = @posts[0]
    assert_equal "/api/ingest/log", path
    assert_equal true, forced

    entries = body["entries"]
    assert_equal 2, entries.size
    assert_equal "info", entries[0]["level"]
    assert_equal "first message", entries[0]["message"]
    assert_equal "ruby", entries[0]["source"]
    assert_kind_of Float, entries[0]["timestamp"]

    # "warning" normalizes to "warn"; attributes keep scalars and JSON-encode nested values.
    assert_equal "warn", entries[1]["level"]
    assert_equal 7, entries[1]["attributes"]["user_id"]
    assert_equal "{\"a\":1}", entries[1]["attributes"]["payload"]
  end

  def test_buffer_auto_flushes_when_it_fills
    ENV["LOOKOUT_LOGS_MAX_BUFFER"] = "3"
    L.instance_variable_set(:@logs_max_buffer, nil) # re-read the env
    3.times { |i| L.log(:error, "msg #{i}") }

    # Auto-flush posts off-thread; give it a moment.
    20.times { break unless @posts.empty?; sleep 0.01 }
    assert_equal 1, @posts.size
    assert_equal 3, @posts[0][1]["entries"].size
  ensure
    ENV.delete("LOOKOUT_LOGS_MAX_BUFFER")
    L.instance_variable_set(:@logs_max_buffer, nil)
  end

  def test_no_op_when_logs_disabled
    ENV["LOOKOUT_LOGS_ENABLED"] = "0"
    L.log(:error, "should not buffer")
    L.flush_logs!
    assert_empty @posts
  end
end
