# frozen_string_literal: true

# Covers the Authentication watcher: Warden hooks → record_auth_event → POST /api/ingest/auth.
# Stubs post_to to capture the (off-thread) outgoing (path, body, env_forced).
#
# Run: ruby packages/lookout-rails/test/auth_test.rb

require "minitest/autorun"
require_relative "../lib/lookout_framework"

class AuthTest < Minitest::Test
  L = LookoutFramework

  FakeUser = Struct.new(:id, :email)
  FakeRequest = Struct.new(:ip, :user_agent)

  # Minimal Warden-proxy stand-in exposing the Rack request, like the real proxy passed to hooks.
  class FakeProxy
    attr_reader :request

    def initialize(request)
      @request = request
    end
  end

  def setup
    @prev = ENV["LOOKOUT_AUTH_ENABLED"]
    ENV["LOOKOUT_AUTH_ENABLED"] = "1"
    L.api_key = "test-key"
    L.base_uri = "https://lookout.test"
    @posts = []
    sink = method(:record)
    L.define_singleton_method(:post_to) { |path, body, env_forced: false| sink.call(path, body, env_forced) }
    Thread.current[:_lookout_trace] = nil
  end

  def teardown
    @prev.nil? ? ENV.delete("LOOKOUT_AUTH_ENABLED") : ENV["LOOKOUT_AUTH_ENABLED"] = @prev
  end

  def record(path, body, forced)
    @posts << [path, body, forced]
  end

  # record_auth_event posts off-thread; poll briefly for the captured post.
  def await
    30.times { break unless @posts.empty?; sleep 0.01 }
    @posts.first
  end

  def proxy_for(ip: "203.0.113.7", ua: "Mozilla/5.0 (Test)")
    FakeProxy.new(FakeRequest.new(ip, ua))
  end

  def test_login_event_posts_to_auth_endpoint_with_user_and_request_context
    user = FakeUser.new(42, "ada@example.com")
    L.send(:record_auth_event, "login", user, proxy_for, { scope: :user, remember: true })

    path, body, forced = await
    refute_nil path, "record_auth_event should post off-thread"
    assert_equal "/api/ingest/auth", path
    assert_equal "login", body["event_type"]
    assert_equal "user", body["guard"]
    assert_equal "42", body["auth_user_id"]
    assert_equal "ada@example.com", body["auth_user_label"]
    assert_equal "203.0.113.7", body["ip_address"]
    assert_equal "Mozilla/5.0 (Test)", body["user_agent"]
    assert_equal true, body["remember"]
    assert_equal true, forced
  end

  def test_logout_event
    user = FakeUser.new(7, "grace@example.com")
    L.send(:record_auth_event, "logout", user, proxy_for, { scope: :user })

    _, body, = await
    assert_equal "logout", body["event_type"]
    assert_equal "7", body["auth_user_id"]
  end

  def test_failed_event_with_nil_user_does_not_raise
    L.send(:record_auth_event, "failed", nil, proxy_for, { scope: :user })

    _, body, = await
    assert_equal "failed", body["event_type"]
    refute body.key?("auth_user_id")
    refute body.key?("auth_user_label")
    assert_equal "203.0.113.7", body["ip_address"]
  end

  def test_never_leaks_password_or_credentials
    user = FakeUser.new(1, "leak@example.com")
    L.send(:record_auth_event, "login", user, proxy_for, { scope: :user, password: "hunter2", credentials: { password: "hunter2" } })

    _, body, = await
    refute body.key?("password"), "auth event must not carry a password"
    refute body.key?("credentials"), "auth event must not carry credentials"
    assert_equal JSON.generate(body).downcase.include?("hunter2"), false
  end
end
