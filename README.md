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
| `LOOKOUT_PERFORMANCE_ENABLED` | `1` to capture HTTP **request traces** (env > site; force-accepts via `X-Lookout-Env-Forced`). Unset = follow the dashboard |
| `LOOKOUT_TRACE_MAX_SPANS` | Cap on child spans per request trace (default `190`, server allows 200 incl. root) |
| `LOOKOUT_JOBS_ENABLED` | `1` to send **Active Job** runs to the Queues watcher (env > site; force-accepts via `X-Lookout-Env-Forced`). Unset = follow the dashboard |
| `LOOKOUT_REMOTE_CONFIG` | `0` to disable fetching per-project config from the dashboard (default on) |
| `LOOKOUT_REMOTE_CONFIG_TTL` | Seconds to cache the fetched config in-process (default `300`) |
| `LOOKOUT_DUMPS_ENABLED` | Local override for the **dumps** signal (env > site); unset = follow the dashboard |

### Signal control: dashboard + env override

Errors are always sent. **Dumps** (`LookoutFramework.dump(value)`) are gated by the Lookout dashboard (**Project → Monitoring → Signals**): the SDK fetches **`GET /api/config`** at boot (cached in-process for `LOOKOUT_REMOTE_CONFIG_TTL`) and stops sending dumps when the project has them off. Precedence is **env > site** — set `LOOKOUT_DUMPS_ENABLED=true|false` to override; when env force-enables dumps the SDK sends **`X-Lookout-Env-Forced`** so the server accepts them, and reports the override so the dashboard shows it as "Set by env."

### Request traces (Requests / performance)

Set `LOOKOUT_PERFORMANCE_ENABLED=1` (or turn the **traces** signal on in the dashboard) and every controller request is captured as a trace: a root **`http.server`** span (`description: "GET /path"`, `data`: `http.method`, `http.route` = `Controller#action`, `http.status_code`, `db.query_count`) plus one **`db.query`** child span per executed SQL statement (cached reads skipped). These power the **Requests** tab. Traces are built in a request-scoped, thread-local buffer and **posted off-thread** to `POST /api/ingest/trace` so they add no latency to the response — byte-compatible with the Laravel `lookout/tracing` payload (32-hex `trace_id`, 16-hex `span_id`, epoch-second timestamps).

Performance ingest is **opt-in on the server** (`projects.performance_ingest_enabled` defaults off), so unlike errors/dumps it defaults OFF here; enabling via env sends `X-Lookout-Env-Forced` so the server accepts it regardless of the dashboard toggle. SQL child spans require `LOOKOUT_PERFORMANCE_ENABLED` (or the dashboard signal) to be on **at boot**.

### CLI / rake commands (Commands)

Rails has no `CommandStarting` event like artisan, so command runs are captured with an explicit wrapper (gated by the same performance signal — `LOOKOUT_PERFORMANCE_ENABLED=1` or the dashboard):

```ruby
namespace :reports do
  task nightly: :environment do
    LookoutFramework.command("rake reports:nightly") do
      # ...your task body; SQL run here becomes db.query child spans...
    end
  end
end
```

It records a root **`console.command`** trace span (`description` = the name you pass, `data.exit_code`, `status` `ok`/`error`) and posts it **synchronously** to `/api/ingest/trace` (a CLI process exits the moment the block returns, so an off-thread post would be lost). It re-raises on failure so the task still exits non-zero. These populate the **Commands** watcher (trace roots where `op = console.command`).

### Active Job runs (Queues)

Set `LOOKOUT_JOBS_ENABLED=1` (or turn the **jobs** signal on in the dashboard) and every Active Job execution is reported to the **Queues** watcher as a two-phase run: `POST /api/ingest/job` with `status:"in_progress"` from `perform_start.active_job` (a fresh client-generated `run_id`), then `status:"ok"|"error"` from `perform.active_job` with the same `run_id`, the `duration`, and — on failure — the `exception` (`class`/`message`/`stack`). Each run carries `queue`, `connection` (the queue adapter), and `attempt` (`executions`). Posts are synchronous so the in-progress row exists before the completion updates it (the server upserts by `run_id`). Same opt-in/env-forced semantics as traces.

## What gets recorded

- **Request traces** — root `http.server` span + `db.query` children → **Requests** tab (opt-in, see above)
- **CLI / rake commands** — `LookoutFramework.command(name) { … }` → root `console.command` span → **Commands** tab (opt-in, see above)
- **Active Job runs** — `in_progress` → `ok`/`error` per execution → **Queues** tab (opt-in, see above)
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
