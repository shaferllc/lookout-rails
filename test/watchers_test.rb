# frozen_string_literal: true

# Covers the remaining watcher ingest paths: events, gates, metrics, models, mail, batches, cron,
# user feedback. Stubs post_to to capture each outgoing (path, body, env_forced).
#
# Run: ruby packages/lookout-rails/test/watchers_test.rb

require "minitest/autorun"
require_relative "../lib/lookout_framework"

class WatchersTest < Minitest::Test
  L = LookoutFramework
  SIGNALS = %w[EVENTS GATES METRICS MODELS MAIL CRON BATCHES FEEDBACK].freeze

  class FakeModel
    def id
      7
    end

    def saved_changes
      { "name" => %w[a b], "updated_at" => [1, 2] }
    end
  end

  def setup
    @prev = {}
    SIGNALS.each do |s|
      @prev[s] = ENV["LOOKOUT_#{s}_ENABLED"]
      ENV["LOOKOUT_#{s}_ENABLED"] = "1"
    end
    L.api_key = "test-key"
    L.base_uri = "https://lookout.test"
    @posts = []
    sink = method(:record)
    L.define_singleton_method(:post_to) { |path, body, env_forced: false| sink.call(path, body, env_forced) }
    L.instance_variable_set(:@signal_buffers, {})
    Thread.current[:_lookout_trace] = nil
  end

  def teardown
    SIGNALS.each { |s| @prev[s].nil? ? ENV.delete("LOOKOUT_#{s}_ENABLED") : ENV["LOOKOUT_#{s}_ENABLED"] = @prev[s] }
    L.instance_variable_set(:@signal_buffers, {})
  end

  def record(path, body, forced)
    @posts << [path, body, forced]
  end

  def find(path)
    @posts.find { |p| p[0] == path }
  end

  def await(path)
    30.times { break if find(path); sleep 0.01 }
    find(path)
  end

  def test_event
    L.event("App::Events::OrderPlaced", listeners: 3, broadcast: true, meta: { a: 1 })
    L.send(:flush_all_signals!, async: false)
    _, body, forced = find("/api/ingest/event")
    entry = body["entries"].first
    assert_equal "App::Events::OrderPlaced", entry["event"]
    assert_equal 3, entry["listeners"]
    assert_equal true, entry["broadcast"]
    assert_equal true, forced
  end

  def test_gate_returns_allowed_and_records_result
    assert_equal false, L.gate("update", allowed: false, user: 42, target: "Post")
    L.send(:flush_all_signals!, async: false)
    entry = find("/api/ingest/gate")[1]["entries"].first
    assert_equal "update", entry["ability"]
    assert_equal "denied", entry["result"]
    assert_equal "42", entry["user"]
    assert_equal "Post", entry["target"]
  end

  def test_metrics_counter_gauge_distribution
    L.gauge("queue.depth", 4, unit: "1", attributes: { region: "us" })
    L.count("orders", 2)
    L.distribution("latency", 12.5, unit: "ms")
    L.send(:flush_all_signals!, async: false)
    entries = find("/api/ingest/metric")[1]["entries"]
    assert_equal 3, entries.size
    assert_equal %w[gauge counter distribution].sort, entries.map { |e| e["kind"] }.sort
    g = entries.find { |e| e["name"] == "queue.depth" }
    assert_equal 4.0, g["value"]
    assert_equal "us", g["attributes"]["region"]
  end

  def test_metric_rejects_non_finite_value
    L.gauge("x", Float::INFINITY)
    L.send(:flush_all_signals!, async: false)
    assert_nil find("/api/ingest/metric")
  end

  def test_model_change_updated_records_changed_keys
    L.send(:record_model_change, FakeModel.new, "updated")
    L.send(:flush_all_signals!, async: false)
    entry = find("/api/ingest/model")[1]["entries"].first
    assert_match(/FakeModel\z/, entry["model"])
    assert_equal "updated", entry["change"]
    assert_equal "7", entry["key"]
    assert_equal ["name"], entry["changes"] # updated_at filtered out
  end

  def test_mail_record_from_notification_payload
    L.send(:report_mail, { mailer: "UserMailer", subject: "Hi", to: ["a@b.com"], date: Time.at(1_700_000_000) })
    body = await("/api/ingest/mail")[1]
    assert_equal "UserMailer", body["mailable"]
    assert_equal "Hi", body["subject"]
    assert_equal ["a@b.com"], body["to"]
    assert_equal "sent", body["meta"]["status"]
  end

  def test_batch_upsert_payload
    L.batch("batch-1", name: "Import", total_jobs: 10, pending_jobs: 0, failed_jobs: 0, finished_at: Time.at(1_700_000_000))
    body = await("/api/ingest/batch")[1]
    assert_equal "batch-1", body["batch_id"]
    assert_equal 10, body["total_jobs"]
    assert body["finished_at"]
  end

  def test_cron_two_phase_success
    assert_equal 7, L.cron("nightly") { 7 }
    crons = @posts.select { |p| p[0] == "/api/ingest/cron" }
    assert_equal 2, crons.size
    assert_equal "in_progress", crons[0][1]["status"]
    assert_equal "ok", crons[1][1]["status"]
    assert_equal crons[0][1]["check_in_id"], crons[1][1]["check_in_id"]
    assert_operator crons[1][1]["duration"], :>=, 0
  end

  def test_cron_failure_reports_error_and_reraises
    assert_raises(RuntimeError) { L.cron("boom") { raise "x" } }
    crons = @posts.select { |p| p[0] == "/api/ingest/cron" }
    assert_equal "error", crons.last[1]["status"]
  end

  def test_user_feedback
    L.user_feedback(comments: "bug here", occurrence_uuid: "550e8400-e29b-41d4-a716-446655440000", name: "Jamie")
    body = await("/api/ingest/feedback")[1]
    assert_equal "bug here", body["comments"]
    assert_equal "550e8400-e29b-41d4-a716-446655440000", body["occurrence_uuid"]
    assert_equal "Jamie", body["name"]
  end
end
