# frozen_string_literal: true

# Tests the request breadcrumb instrumentation against real ActiveSupport::Notifications events.
# Locks in two fixes found while testing the plugin against a live Rails app:
#   1. process_action.action_controller's payload[:controller] is the controller class *name*
#      (a String) — it must be used directly, not via .class.name (which yielded "String").
#   2. the per-request reset + dispatch breadcrumb must subscribe to the event Rails actually emits,
#      "start_processing.action_controller" (not ".action_dispatch", which never fires).
#
# Run: ruby packages/lookout-rails/test/breadcrumb_test.rb  (needs the activesupport gem)

require "minitest/autorun"
require "active_support"
require "active_support/notifications"
require_relative "../lib/lookout_framework"

class BreadcrumbTest < Minitest::Test
  L = LookoutFramework

  def setup
    # No network: report_* and dump short-circuit when api_key/base_uri are blank.
    L.api_key = ""
    L.base_uri = ""
    L.install! # idempotent; subscribes the AS::Notifications handlers once
    crumbs.clear
  end

  def crumbs
    L.send(:store).breadcrumbs
  end

  def test_dispatch_event_resets_store_and_records_method_and_path
    crumbs << { "type" => "stale", "message" => "from a previous request" }

    ActiveSupport::Notifications.instrument(
      "start_processing.action_controller", method: "GET", path: "/widgets/42"
    ) { nil }

    assert_equal 1, crumbs.size, "store should be reset at the start of a request"
    assert_equal "GET /widgets/42", crumbs.last["message"]
    assert_equal "dispatch", crumbs.last["category"]
  end

  def test_controller_breadcrumb_uses_controller_name_not_string
    ActiveSupport::Notifications.instrument(
      "process_action.action_controller", controller: "WidgetsController", action: "show", status: 200
    ) { nil }

    msg = crumbs.last["message"]
    assert_equal "WidgetsController#show → 200", msg
    refute_includes msg, "String#", "payload[:controller] is the class name string, not an instance"
  end
end
