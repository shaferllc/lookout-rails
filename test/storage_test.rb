# frozen_string_literal: true

# Covers the Storage watcher: ActiveStorage service ops → file.* child spans in the request trace,
# posted to /api/ingest/trace. Mirrors trace_test.rb (stubbed post_trace, no network).
#
# Run: ruby packages/lookout-rails/test/storage_test.rb

require "minitest/autorun"
require_relative "../lib/lookout_framework"

class StorageTest < Minitest::Test
  L = LookoutFramework

  def setup
    @prev_perf = ENV["LOOKOUT_PERFORMANCE_ENABLED"]
    ENV["LOOKOUT_PERFORMANCE_ENABLED"] = "1" # env override → traces_enabled? true, no network
    L.api_key = "test-key"
    L.base_uri = "https://lookout.test"
    @captured = nil
    cap = method(:capture)
    L.define_singleton_method(:post_trace) { |body, env_forced: false| cap.call(body) }
  end

  def teardown
    @prev_perf.nil? ? ENV.delete("LOOKOUT_PERFORMANCE_ENABLED") : ENV["LOOKOUT_PERFORMANCE_ENABLED"] = @prev_perf
    Thread.current[:_lookout_trace] = nil
  end

  def capture(body)
    @captured = body
  end

  def test_records_file_write_read_delete_spans
    L.send(:begin_trace!, "POST", "/uploads")
    L.send(:record_storage_span, "file.write", 1000.0, 1000.02, { key: "uploads/x.png", service: "amazon", byte_size: 1234 })
    L.send(:record_storage_span, "file.read", 1001.0, 1001.01, { key: "uploads/x.png", service: "amazon" })
    L.send(:record_storage_span, "file.delete", 1002.0, 1002.005, { key: "uploads/x.png", service: "amazon" })
    L.send(:finish_trace!, { controller: "UploadsController", action: "create", status: 201 }, nil)

    refute_nil @captured, "finish_trace! should post a trace body"
    spans = @captured["spans"]
    file_spans = spans.select { |s| s["op"].to_s.start_with?("file.") }
    assert_equal %w[file.write file.read file.delete], file_spans.map { |s| s["op"] }

    write = file_spans.first
    assert_equal "uploads/x.png", write["data"]["file.path"]
    assert_equal "amazon", write["data"]["file.disk"]
    assert_equal 1234, write["data"]["file.bytes"]
    assert write["data"].key?("file.duration_ms")
    file_spans.each { |s| assert_match(/\A[0-9a-f]{16}\z/, s["span_id"]) }
  end

  def test_no_file_contents_in_span_data
    L.send(:begin_trace!, "POST", "/uploads")
    L.send(:record_storage_span, "file.write", 1000.0, 1000.02, { key: "secret.txt", service: "disk", byte_size: 5, io: "TOPSECRET" })
    L.send(:finish_trace!, { controller: "X", action: "y", status: 200 }, nil)

    json = JSON.generate(@captured)
    refute json.include?("TOPSECRET"), "span payload must never carry file contents"
  end

  def test_storage_span_is_a_noop_without_active_trace
    Thread.current[:_lookout_trace] = nil
    # Should not raise and should record nothing when no trace is active.
    assert_nil L.send(:record_storage_span, "file.read", 1.0, 1.1, { key: "a", service: "disk" })
  end
end
