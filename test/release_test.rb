# frozen_string_literal: true

# Tests that error-path ingest bodies (report_exception, report_http_not_found) carry the
# top-level `release` field sourced from LOOKOUT_RELEASE, via the single post_ingest choke point.
#
# Run: ruby packages/lookout-rails/test/release_test.rb

require "minitest/autorun"
require_relative "../lib/lookout_framework"

class ReleaseTest < Minitest::Test
  L = LookoutFramework

  # Minimal stand-in for an ActionDispatch::Request-like object.
  class FakeRequest
    def request_method
      "GET"
    end

    def fullpath
      "/missing"
    end

    def original_url
      "https://lookout.test/missing"
    end
  end

  def setup
    @prev_release = ENV["LOOKOUT_RELEASE"]
    L.api_key = "test-key"
    L.base_uri = "https://lookout.test"
    L.instance_variable_set(:@release, nil)
    freeze_remote({})
    @posts = []
    sink = method(:record)
    # Stub post_to (not post_ingest) so the fix under test -- which lives inside post_ingest,
    # the single choke point both error entry points funnel through -- actually executes.
    L.define_singleton_method(:post_to) { |_path, body, env_forced: false| sink.call(body) }
  end

  def teardown
    if @prev_release.nil?
      ENV.delete("LOOKOUT_RELEASE")
    else
      ENV["LOOKOUT_RELEASE"] = @prev_release
    end
    L.instance_variable_set(:@release, nil)
  end

  def freeze_remote(config)
    L.instance_variable_set(:@remote_config, config)
    L.instance_variable_set(:@remote_config_at, Process.clock_gettime(Process::CLOCK_MONOTONIC))
    L.instance_variable_set(:@remote_config_ttl, 300)
  end

  def record(body)
    @posts << body
  end

  def test_report_exception_includes_release_when_set
    ENV["LOOKOUT_RELEASE"] = "1.4.2"
    L.instance_variable_set(:@release, nil)

    L.report_exception(RuntimeError.new("boom"))

    assert_equal 1, @posts.size
    assert_equal "1.4.2", @posts[0]["release"]
  end

  def test_report_http_not_found_includes_release_when_set
    ENV["LOOKOUT_RELEASE"] = "1.4.2"
    L.instance_variable_set(:@release, nil)

    L.report_http_not_found(request: FakeRequest.new)

    assert_equal 1, @posts.size
    assert_equal "1.4.2", @posts[0]["release"]
  end

  def test_release_key_absent_when_unset
    ENV.delete("LOOKOUT_RELEASE")
    L.instance_variable_set(:@release, nil)

    L.report_exception(RuntimeError.new("boom"))

    assert_equal 1, @posts.size
    refute @posts[0].key?("release"), "release key must be omitted, not sent empty"
  end
end
