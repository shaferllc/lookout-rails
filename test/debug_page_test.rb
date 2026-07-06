# frozen_string_literal: true

# Tests the local debug page ("Lookout's Ignition", Rails edition): headline,
# source snippet extraction from real files, breadcrumbs, the copy-markdown
# island, and the middleware's enabled/disabled behavior.
#
# Run: ruby packages/lookout-rails/test/debug_page_test.rb

require "minitest/autorun"
require_relative "../lib/lookout_framework"

class DebugPageTest < Minitest::Test
  L = LookoutFramework

  def setup
    L.api_key = ""
    L.base_uri = ""
    ENV.delete("LOOKOUT_DEBUG_PAGE")
  end

  def boom
    raise ArgumentError, "server 42 cannot be restarted"
  rescue ArgumentError => e
    e
  end

  def test_renders_headline_source_and_markdown_island
    html = L::DebugPage.new.render(boom, breadcrumbs: [], context: { "ruby_version" => RUBY_VERSION })

    assert_includes html, "ArgumentError"
    assert_includes html, "server 42 cannot be restarted"
    # the raising line from THIS file, read off disk
    assert_includes html, "cannot be restarted&quot;"
    assert_includes html, "debug_page_test.rb"
    assert_includes html, "lk-copy-data"
    assert_includes html, "Copy as Markdown"
    # markdown island escapes < so a </script> in source can't break out
    refute_includes html.split("lk-copy-data").last.split("</script>").first, "</"
  end

  def test_renders_breadcrumbs_newest_first
    # Sentinels are built at runtime so they can't appear in this file's source
    # snippets (the page shows the raising test file's source too).
    older = "crumb-" + "older"
    newer = "crumb-" + "newer"
    crumbs = [
      { "level" => "info", "category" => "routing", "message" => older },
      { "level" => "debug", "category" => "db", "message" => newer }
    ]
    html = L::DebugPage.new.render(boom, breadcrumbs: crumbs)

    assert_includes html, "Breadcrumbs (2)"
    assert_includes html, newer
    assert html.index(newer) < html.index(older), "breadcrumbs should render newest first"
  end

  def test_markdown_report_contains_stack_and_crumbs
    md = L::DebugPage.new.send(:build_markdown, "ArgumentError", "boom",
      [{ file: "app/models/server.rb", line: 10, function: "restart" }],
      [{ "level" => "info", "category" => "routing", "message" => "matched" }],
      { "ruby_version" => RUBY_VERSION })

    assert_includes md, "# ArgumentError: boom"
    assert_includes md, "#0 app/models/server.rb:10  restart"
    assert_includes md, "- `info` **routing** matched"
    assert_includes md, "- **ruby_version:** #{RUBY_VERSION}"
  end

  def test_debug_page_enabled_env_flag
    ENV["LOOKOUT_DEBUG_PAGE"] = "true"
    assert L.debug_page_enabled?

    ENV["LOOKOUT_DEBUG_PAGE"] = "false"
    refute L.debug_page_enabled?
  ensure
    ENV.delete("LOOKOUT_DEBUG_PAGE")
  end

  def test_middleware_reraises_when_disabled
    ENV["LOOKOUT_DEBUG_PAGE"] = "false"
    app = ->(_env) { raise "kaboom" }
    mw = L::DebugMiddleware.new(app)

    assert_raises(RuntimeError) { mw.call({}) }
  ensure
    ENV.delete("LOOKOUT_DEBUG_PAGE")
  end

  def test_middleware_renders_page_when_enabled
    ENV["LOOKOUT_DEBUG_PAGE"] = "true"
    app = ->(_env) { raise "kaboom" }
    status, headers, body = L::DebugMiddleware.new(app).call({})

    assert_equal 500, status
    assert_includes headers["Content-Type"], "text/html"
    assert_includes body.join, "kaboom"
  ensure
    ENV.delete("LOOKOUT_DEBUG_PAGE")
  end
end
