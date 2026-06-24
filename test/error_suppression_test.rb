# frozen_string_literal: true

# Standalone test for the client error-suppression key + remote "suppress" list in the Rails SDK.
# Run: ruby packages/lookout-rails/test/error_suppression_test.rb

require "minitest/autorun"
require_relative "../lib/lookout_framework"

class ErrorSuppressionTest < Minitest::Test
  L = LookoutFramework

  def freeze_remote(config)
    L.instance_variable_set(:@remote_config, config)
    L.instance_variable_set(:@remote_config_at, Process.clock_gettime(Process::CLOCK_MONOTONIC))
    L.instance_variable_set(:@remote_config_ttl, 300)
  end

  def test_key_matches_the_server_recipe_byte_for_byte
    # Cross-checked against App\Support\ErrorSuppressionKey::compute so SDK + server agree.
    assert_equal "39ef0cde2ebd1a398fdb287a1c103895",
      L.suppression_key("App\\Exceptions\\Boom", "User 4212 not found")
  end

  def test_volatile_tokens_collapse_occurrences_to_one_key
    a = L.suppression_key("X", "HTTP 404 Not Found: GET /storage/logos/01ktb3fn7n0me349kth61ydqy6rvqos.png")
    b = L.suppression_key("X", "HTTP 404 Not Found: GET /storage/logos/02abckj9zz8x71239aaa00bbb1zzzzz.png")
    assert_equal a, b
  end

  def test_error_suppressed_when_key_is_in_remote_list
    key = L.suppression_key("App\\Exceptions\\Boom", "Boom happened")
    freeze_remote("suppress" => [key])
    assert_equal true, L.error_suppressed?("App\\Exceptions\\Boom", "Boom happened")
    assert_equal false, L.error_suppressed?("App\\Exceptions\\Other", "Different error")
  end

  def test_not_suppressed_when_list_absent_or_empty
    freeze_remote({})
    assert_equal false, L.error_suppressed?("App\\Exceptions\\Boom", "Boom happened")
    freeze_remote("suppress" => [])
    assert_equal false, L.error_suppressed?("App\\Exceptions\\Boom", "Boom happened")
  end
end
