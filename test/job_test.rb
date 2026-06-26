# frozen_string_literal: true

# Tests the Active Job → Queues ingest: a two-phase job run (in_progress → ok/error) posted to
# /api/ingest/job with a client-generated run_id, mirroring the Laravel lookout-tracing job client.
#
# Run: ruby packages/lookout-rails/test/job_test.rb

require "minitest/autorun"
require_relative "../lib/lookout_framework"

class JobTest < Minitest::Test
  L = LookoutFramework
  UUID_V4 = /\A[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/i

  # Minimal stand-in for an ActiveJob instance.
  class FakeJob
    def self.queue_adapter_name
      "async"
    end

    attr_reader :job_id, :queue_name, :executions

    def initialize(job_id: "job-1", queue_name: "default", executions: 1)
      @job_id = job_id
      @queue_name = queue_name
      @executions = executions
    end
  end

  def setup
    @prev = ENV["LOOKOUT_JOBS_ENABLED"]
    ENV["LOOKOUT_JOBS_ENABLED"] = "1"
    L.api_key = "test-key"
    L.base_uri = "https://lookout.test"
    @posts = []
    sink = method(:record)
    L.define_singleton_method(:post_job) { |body, env_forced: (jobs_env_override == true)| sink.call(body, env_forced) }
    Thread.current[:_lookout_job_runs] = nil
  end

  def teardown
    if @prev.nil?
      ENV.delete("LOOKOUT_JOBS_ENABLED")
    else
      ENV["LOOKOUT_JOBS_ENABLED"] = @prev
    end
    Thread.current[:_lookout_job_runs] = nil
  end

  def record(body, forced)
    @posts << [body, forced]
  end

  def test_successful_job_posts_in_progress_then_ok_with_same_run_id
    job = FakeJob.new
    L.send(:begin_job_run!, job)
    L.send(:finish_job_run!, { job: job })

    assert_equal 2, @posts.size
    started, started_forced = @posts[0]
    finished, = @posts[1]

    assert_match(/FakeJob\z/, started["job"])
    assert_equal "in_progress", started["status"]
    assert_match UUID_V4, started["run_id"]
    assert_equal "default", started["queue"]
    assert_equal "async", started["connection"]
    assert_equal 1, started["attempt"]
    assert_equal true, started_forced, "env override should force-accept the signal"

    assert_equal "ok", finished["status"]
    assert_equal started["run_id"], finished["run_id"], "completion must reuse the in_progress run_id"
    assert_kind_of Float, finished["duration"]
    refute finished.key?("exception")
  end

  def test_failed_job_reports_error_status_and_exception
    job = FakeJob.new(job_id: "job-2")
    L.send(:begin_job_run!, job)
    boom = RuntimeError.new("kaboom")
    boom.set_backtrace(["app/jobs/hello_job.rb:9:in `perform'"])
    L.send(:finish_job_run!, { job: job, exception_object: boom })

    finished = @posts[1][0]
    assert_equal "error", finished["status"]
    assert_equal "RuntimeError", finished["exception"]["class"]
    assert_equal "kaboom", finished["exception"]["message"]
    assert_includes finished["exception"]["stack"], "hello_job.rb"
  end

  def test_completion_without_a_started_run_is_a_noop
    job = FakeJob.new(job_id: "never-started")
    L.send(:finish_job_run!, { job: job })
    assert_empty @posts, "no in_progress row was opened, so nothing should post"
  end
end
