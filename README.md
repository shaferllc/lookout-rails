# Lookout Rails integration

Copy-paste **Ruby on Rails** instrumentation (not a published gem) that mirrors what `lookout/tracing` does for Laravel: breadcrumbs for HTTP, Active Job, and optional SQL / custom `ActiveSupport::Notifications`, plus posting uncaught errors to Lookout’s `POST /api/ingest`.

**Location in the Lookout monorepo:** `packages/lookout-rails/`. This directory is **git subtree split** to a standalone mirror repository when `SPLIT_LOOKOUT_RAILS_REPO` is configured (same pattern as `lookout/cli` and `lookout/tracing`).

## Setup

1. Copy `lib/lookout_framework.rb` into your app (e.g. `config/initializers/lookout_framework.rb`) and set:

   - `LookoutFramework.api_key` — project API key from Lookout
   - `LookoutFramework.base_uri` — e.g. `https://your-lookout-host.example`

2. In `config/application.rb` (or an initializer after Rails loads), call:

   ```ruby
   LookoutFramework.install!
   ```

3. To **report exceptions** to Lookout, call `LookoutFramework.report_exception(exception)` from your error notifier (e.g. after `Rails.error.report` on Rails 7+, or inside `config.exceptions_app`, or your APM’s error hook). There is no one-size-fits-all entry point across Rails versions—wire the method where your app already centralizes exceptions.

## Environment variables

| Variable | Purpose |
|----------|---------|
| `LOOKOUT_API_KEY` | Project API key |
| `LOOKOUT_BASE_URI` | Lookout origin (no trailing slash) |
| `LOOKOUT_INSTRUMENT_SQL` | `1` to record sampled `sql.active_record` breadcrumbs |

## What gets recorded

- **Action Controller** — `process_action.action_controller` (controller#action, status, path)
- **Active Job** — `perform_start.active_job`, `perform.active_job`, `enqueue.active_job`, `discard.active_job`, `retry_stopped.active_job`
- **Optional SQL** — `sql.active_record` (every *n*th query; SQL truncated)
- **Custom** — add `LookoutFramework.subscribe_notification("my.event")` for app-specific events

Breadcrumbs are stored in a **request- or job-scoped** store (`ActiveSupport::IsolatedExecutionState` when available) so threaded servers do not mix contexts.

Errors are sent as JSON with `message`, `exception_class`, `stack_trace`, `language: "ruby"`, `breadcrumbs`, and `context.ruby` (Rails version, route, job class).

## Lookout ingest

Same contract as your Lookout instance’s **Ingest API** (`/docs` on the app): `POST /api/ingest` or `POST /api/v1/errors` with `X-Api-Key` or `X-Api-Token` (the Ruby sample sends `api_key` in the JSON body as well).

For distributed tracing, use your preferred OpenTelemetry (or similar) propagation and attach `trace_id` / `span_id` fields on the error payload if you correlate manually.

## Unified onboarding

On your Lookout host, open **GET `/docs/packages`** for how this module fits next to `lookout/tracing`, the CLI, RUM, and browser embed JS.
