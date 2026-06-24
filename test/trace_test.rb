# frozen_string_literal: true

# Tests the request-trace builder: a root http.server span plus db.query child spans, posted to
# /api/ingest/trace. Mirrors the Laravel lookout-tracing payload (32-hex trace_id, 16-hex span_id,
# epoch-second timestamps, op="http.server" root with http.* data).
#
# Run: ruby packages/lookout-rails/test/trace_test.rb

require "minitest/autorun"
require_relative "../lib/lookout_framework"

class TraceTest < Minitest::Test
  L = LookoutFramework

  def setup
    @prev_perf = ENV["LOOKOUT_PERFORMANCE_ENABLED"]
    ENV["LOOKOUT_PERFORMANCE_ENABLED"] = "1" # env override → traces_enabled? true, no network
    L.api_key = "test-key"
    L.base_uri = "https://lookout.test"
    @captured = nil
    @forced = nil
    # Stub the off-thread network post so we can inspect the built body synchronously.
    cap = method(:capture)
    L.define_singleton_method(:post_trace) { |body, env_forced: false| cap.call(body, env_forced) }
  end

  def teardown
    if @prev_perf.nil?
      ENV.delete("LOOKOUT_PERFORMANCE_ENABLED")
    else
      ENV["LOOKOUT_PERFORMANCE_ENABLED"] = @prev_perf
    end
    Thread.current[:_lookout_trace] = nil
  end

  def capture(body, forced)
    @captured = body
    @forced = forced
  end

  def test_builds_http_server_trace_with_db_child_span
    L.send(:begin_trace!, "GET", "/widgets/42")
    L.send(:record_query_span, { sql: "SELECT * FROM widgets WHERE id = 42", cached: false, name: "Widget Load" }, 1000.0, 1000.05)
    L.send(:finish_trace!, { controller: "WidgetsController", action: "show", status: 200 }, nil)

    refute_nil @captured, "finish_trace! should post a trace body"
    assert_match(/\A[0-9a-f]{32}\z/, @captured["trace_id"])
    assert_equal "GET /widgets/42", @captured["transaction"]

    root, child = @captured["spans"]
    assert_equal "http.server", root["op"]
    assert_nil root["parent_span_id"]
    assert_match(/\A[0-9a-f]{16}\z/, root["span_id"])
    assert_equal "GET /widgets/42", root["description"]
    assert_equal "GET", root["data"]["http.method"]
    assert_equal 200, root["data"]["http.status_code"]
    assert_equal "WidgetsController#show", root["data"]["http.route"]
    assert_equal 1, root["data"]["db.query_count"]
    assert_kind_of Float, root["start_timestamp"]
    assert_operator root["end_timestamp"], :>=, root["start_timestamp"]

    assert_equal "db.query", child["op"]
    assert_equal root["span_id"], child["parent_span_id"]
    assert_in_delta 50.0, child["data"]["db.duration_ms"], 0.001
    assert_equal true, @forced, "env-forced override should be sent when LOOKOUT_PERFORMANCE_ENABLED=1"
  end

  def test_uncaught_exception_marks_root_span_as_500_internal_error
    L.send(:begin_trace!, "GET", "/boom")
    L.send(:finish_trace!, { controller: "LookoutTestController", action: "boom", status: nil, exception_object: RuntimeError.new("boom") }, nil)

    root = @captured["spans"].first
    assert_equal "internal_error", root["status"]
    assert_equal 500, root["data"]["http.status_code"]
  end

  def test_cached_queries_do_not_become_spans
    L.send(:begin_trace!, "GET", "/widgets")
    L.send(:record_query_span, { sql: "SELECT * FROM widgets", cached: true, name: "CACHE" }, 1.0, 1.01)
    L.send(:finish_trace!, { controller: "WidgetsController", action: "index", status: 200 }, nil)

    assert_equal 1, @captured["spans"].size, "only the root span — cached reads are skipped"
  end
end
