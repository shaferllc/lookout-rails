# frozen_string_literal: true

# Standalone test for the env > site signal precedence in the Rails SDK.
# Run: ruby packages/lookout-rails/test/remote_config_test.rb

require "minitest/autorun"
require "json"
require "base64"
require_relative "../lib/lookout_framework"

class RemoteConfigTest < Minitest::Test
  L = LookoutFramework

  def freeze_remote(config)
    L.instance_variable_set(:@remote_config, config)
    L.instance_variable_set(:@remote_config_at, Process.clock_gettime(Process::CLOCK_MONOTONIC))
    L.instance_variable_set(:@remote_config_ttl, 300)
  end

  def teardown
    ENV.delete("LOOKOUT_DUMPS_ENABLED")
  end

  def test_default_on_when_nothing_set
    ENV.delete("LOOKOUT_DUMPS_ENABLED")
    freeze_remote({})
    assert_equal true, L.dumps_enabled?
  end

  def test_remote_config_disables_dumps
    ENV.delete("LOOKOUT_DUMPS_ENABLED")
    freeze_remote("signals" => { "dumps" => { "enabled" => false } })
    assert_equal false, L.dumps_enabled?
  end

  def test_env_on_wins_over_remote_off
    ENV["LOOKOUT_DUMPS_ENABLED"] = "true"
    freeze_remote("signals" => { "dumps" => { "enabled" => false } })
    assert_equal true, L.dumps_enabled?
    assert_equal true, L.dumps_env_override
  end

  def test_env_off_wins_over_remote_on
    ENV["LOOKOUT_DUMPS_ENABLED"] = "0"
    freeze_remote("signals" => { "dumps" => { "enabled" => true } })
    assert_equal false, L.dumps_enabled?
  end

  def test_env_overrides_report_only_when_set
    ENV.delete("LOOKOUT_DUMPS_ENABLED")
    assert_nil L.send(:env_overrides_report)

    ENV["LOOKOUT_DUMPS_ENABLED"] = "false"
    decoded = JSON.parse(Base64.strict_decode64(L.send(:env_overrides_report)))
    assert_equal({ "dumps" => { "enabled" => false } }, decoded)
  end
end
