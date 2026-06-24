# frozen_string_literal: true

# Copy into config/initializers/lookout_framework.rb (or lib/) and call LookoutFramework.install!
# See packages/lookout-rails/README.md

require "base64"
require "digest"
require "json"
require "net/http"
require "securerandom"
require "time" # Time#iso8601 (stdlib); under Rails it's already loaded, but don't depend on load order
require "uri"

module LookoutFramework
  # Serializes an arbitrary Ruby value into the same normalized dump tree the PHP/JS SDKs emit:
  # {type, class?, key?, value?, preview?, children?, truncated?, ref?}. Bounded by depth, child
  # count, string length and total size, with cycle detection and key-based redaction so secrets
  # never leave the process.
  class DumpSerializer
    DEFAULT_REDACT_KEYS = %w[
      password pass pwd secret token api_key apikey authorization auth
      access_token refresh_token private_key card card_number cvv cvc ssn
    ].freeze

    def initialize(max_depth: 6, max_children: 100, max_string: 8192, max_total_bytes: 262_144, redact_keys: DEFAULT_REDACT_KEYS)
      @max_depth = max_depth
      @max_children = max_children
      @max_string = max_string
      @max_total_bytes = max_total_bytes
      @redact_keys = redact_keys
    end

    def serialize(value, _label = nil)
      @total_bytes = 0
      @truncated = false
      @seen = {}
      tree = node(value, nil, 0)
      {
        "tree" => tree,
        "preview" => tree["preview"] || describe(value),
        "root_type" => tree["type"] || type_of(value),
        "root_class" => object?(value) ? value.class.name : nil,
        "truncated" => @truncated
      }
    end

    private

    def node(value, key, depth)
      n = {}
      n["key"] = cap(key.to_s, 128) unless key.nil?

      if !key.nil? && redact?(key.to_s)
        @truncated = true
        n["type"] = "redacted"
        n["preview"] = "[redacted]"
        return n
      end

      if depth >= @max_depth
        @truncated = true
        n["type"] = "truncated"
        n["preview"] = describe(value)
        return n
      end

      case value
      when Hash
        with_cycle_guard(n, value) { container(n, value, "array", nil, depth) }
      when Array
        with_cycle_guard(n, value) { container(n, array_pairs(value), "array", nil, depth) }
      when String, Symbol, Integer, Float, TrueClass, FalseClass, NilClass
        scalar(n, value)
      else
        with_cycle_guard(n, value) { container(n, object_props(value), "object", value.class.name, depth) }
      end
    end

    # Reference types (Hash, Array, objects) can form cycles; emit a ref node instead of recursing.
    def with_cycle_guard(n, value)
      oid = value.object_id
      if @seen[oid]
        n["type"] = "ref"
        n["ref"] = oid
        n["preview"] = "#{value.class.name} {ref ##{oid}}"
        return n
      end
      @seen[oid] = true
      result = yield
      @seen.delete(oid)
      result
    end

    def container(n, items, type, klass, depth)
      n["type"] = type
      n["class"] = cap(klass, 255) if klass
      count = items.size
      n["preview"] = klass ? "#{klass} {##{count}}" : "array:#{count} […]"

      children = []
      i = 0
      items.each do |k, v|
        if i >= @max_children
          @truncated = true
          children << { "type" => "truncated", "preview" => "+#{count - @max_children} more" }
          break
        end
        if @total_bytes >= @max_total_bytes
          @truncated = true
          children << { "type" => "truncated", "preview" => "…" }
          break
        end
        children << node(v, k, depth + 1)
        i += 1
      end
      n["children"] = children unless children.empty?
      n
    end

    def scalar(n, value)
      case value
      when String, Symbol
        s = value.to_s
        capped = cap(s, @max_string)
        if capped.bytesize < s.bytesize
          @truncated = true
          n["truncated"] = true
        end
        n["type"] = "string"
        n["value"] = capped
        @total_bytes += capped.bytesize
      when Integer
        n["type"] = "int"
        n["value"] = value
        @total_bytes += 8
      when Float
        n["type"] = "float"
        n["value"] = value
        @total_bytes += 8
      when TrueClass, FalseClass
        n["type"] = "bool"
        n["value"] = value
        @total_bytes += 8
      when NilClass
        n["type"] = "null"
        n["value"] = nil
        @total_bytes += 8
      end
      n
    end

    def array_pairs(arr)
      pairs = {}
      arr.each_with_index { |v, i| pairs[i] = v }
      pairs
    end

    def object_props(value)
      out = {}
      value.instance_variables.each do |ivar|
        out[ivar.to_s.sub(/\A@/, "")] = value.instance_variable_get(ivar)
      end
      out
    rescue StandardError
      {}
    end

    def object?(value)
      !value.is_a?(Hash) && !value.is_a?(Array) &&
        !value.is_a?(String) && !value.is_a?(Symbol) && !value.is_a?(Numeric) &&
        value != true && value != false && !value.nil?
    end

    def type_of(value)
      case value
      when String, Symbol then "string"
      when Integer then "int"
      when Float then "float"
      when TrueClass, FalseClass then "bool"
      when NilClass then "null"
      when Array then "array"
      when Hash then "array"
      else "object"
      end
    end

    def describe(value)
      return value.class.name if object?(value)
      return "array:#{value.size}" if value.is_a?(Array) || value.is_a?(Hash)
      return cap(value.to_s, 64) if value.is_a?(String) || value.is_a?(Symbol)

      value.class.name
    end

    def redact?(key)
      needle = key.downcase
      @redact_keys.any? { |bad| needle == bad || needle.include?(bad) }
    end

    def cap(str, max)
      str.length > max ? str[0, max] : str
    end
  end

  class Store
    attr_reader :breadcrumbs

    def initialize
      @breadcrumbs = []
      @max = 50
    end

    def max=(n)
      @max = [[n.to_i, 1].max, 100].min
    end

    def clear
      @breadcrumbs.clear
    end

    def add(type:, message:, level: "info", category: nil, data: nil)
      row = {
        "type" => type.to_s[0, 64],
        "message" => message.to_s[0, 2000],
        "level" => level.to_s[0, 32],
        "timestamp" => Time.now.utc.iso8601
      }
      row["category"] = category.to_s[0, 128] if category && !category.to_s.empty?
      row["data"] = data if data.is_a?(Hash) && data.any?
      @breadcrumbs << row
      @breadcrumbs.shift while @breadcrumbs.size > @max
    end
  end

  class << self
    attr_writer :api_key, :base_uri, :ingest_path

    def api_key
      @api_key ||= ENV["LOOKOUT_API_KEY"]
    end

    def base_uri
      (@base_uri ||= ENV["LOOKOUT_BASE_URI"]).to_s.sub(%r{/+\z}, "")
    end

    def ingest_path
      @ingest_path ||= ENV.fetch("LOOKOUT_ERROR_INGEST_PATH", "/api/ingest")
    end

    def dump_ingest_path
      @dump_ingest_path ||= ENV.fetch("LOOKOUT_DUMP_INGEST_PATH", "/api/ingest/dump")
    end

    def trace_ingest_path
      @trace_ingest_path ||= ENV.fetch("LOOKOUT_TRACE_INGEST_PATH", "/api/ingest/trace")
    end

    def job_ingest_path
      @job_ingest_path ||= ENV.fetch("LOOKOUT_JOB_INGEST_PATH", "/api/ingest/job")
    end

    # Cap on child spans per request trace (server allows root + 199 children; stay under it).
    def trace_max_spans
      @trace_max_spans ||= [[ENV.fetch("LOOKOUT_TRACE_MAX_SPANS", "190").to_i, 1].max, 199].min
    end

    def environment
      @environment ||= ENV["LOOKOUT_ENVIRONMENT"]
    end

    def max_breadcrumbs
      @max_breadcrumbs ||= ENV.fetch("LOOKOUT_BREADCRUMBS_MAX", "50").to_i
    end

    def sql_sample_every
      @sql_sample_every ||= ENV.fetch("LOOKOUT_INSTRUMENT_DATABASE_SAMPLE_EVERY", "5").to_i
    end

    def remote_config_enabled?
      ENV.fetch("LOOKOUT_REMOTE_CONFIG", "1").to_s != "0"
    end

    def remote_config_ttl
      @remote_config_ttl ||= ENV.fetch("LOOKOUT_REMOTE_CONFIG_TTL", "300").to_i
    end

    # Explicit env override for the dumps signal, or nil when unset. An explicit env var wins over
    # the dashboard (env > site).
    def dumps_env_override
      raw = ENV["LOOKOUT_DUMPS_ENABLED"]
      return nil if raw.nil? || raw.to_s.strip.empty?

      %w[1 true yes on].include?(raw.to_s.strip.downcase)
    end

    # Whether to send dumps: env override wins, else the dashboard's remote config, else default on.
    def dumps_enabled?
      override = dumps_env_override
      return override unless override.nil?

      cfg = remote_config.dig("signals", "dumps", "enabled")
      cfg.nil? ? true : !!cfg
    end

    # Explicit env override for performance/request traces, or nil when unset (env > site).
    def traces_env_override
      raw = ENV["LOOKOUT_PERFORMANCE_ENABLED"]
      return nil if raw.nil? || raw.to_s.strip.empty?

      %w[1 true yes on].include?(raw.to_s.strip.downcase)
    end

    # Whether to capture + send request traces. Unlike dumps, performance ingest is opt-in on the
    # server (projects.performance_ingest_enabled defaults off), so this defaults to OFF: enable it
    # with LOOKOUT_PERFORMANCE_ENABLED=1 (which also force-accepts via X-Lookout-Env-Forced) or by
    # turning the signal on in the dashboard (Project → Monitoring → Signals).
    def traces_enabled?
      override = traces_env_override
      return override unless override.nil?

      !!remote_config.dig("signals", "traces", "enabled")
    end

    # Explicit env override for the Active Job → Queues signal, or nil when unset (env > site).
    def jobs_env_override
      raw = ENV["LOOKOUT_JOBS_ENABLED"]
      return nil if raw.nil? || raw.to_s.strip.empty?

      %w[1 true yes on].include?(raw.to_s.strip.downcase)
    end

    # Whether to send Active Job runs to the Queues watcher. Opt-in on the server
    # (projects.job_ingest_enabled defaults off), so defaults OFF: LOOKOUT_JOBS_ENABLED=1 (also
    # force-accepts via X-Lookout-Env-Forced) or turn the signal on in the dashboard.
    def jobs_enabled?
      override = jobs_env_override
      return override unless override.nil?

      !!remote_config.dig("signals", "jobs", "enabled")
    end

    # Cached per-project ingest config from GET /api/config. Cached in-process for remote_config_ttl
    # seconds (this runs in a long-lived Rails process); refreshed lazily when stale.
    def remote_config
      return {} unless remote_config_enabled?

      now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      if @remote_config && @remote_config_at && (now - @remote_config_at) < remote_config_ttl
        return @remote_config
      end

      @remote_config_at = now
      @remote_config = fetch_remote_config || @remote_config || {}
    end

    # Client suppression key for an error: stable 32-char id from the exception class + a normalized
    # message. When a user ignores an error group in the dashboard the server publishes that group's
    # key in GET /api/config ("suppress"); we drop matches before sending so ignored errors stop
    # re-ingesting. This recipe is a CONTRACT shared byte-for-byte with the server
    # (App\Support\ErrorSuppressionKey) and the other SDKs — keep it identical or bump "lkt_supp_v1".
    def suppression_key(exception_class, message)
      klass = exception_class.to_s.strip.downcase
      Digest::SHA256.hexdigest("lkt_supp_v1|#{klass}|#{normalize_suppression_message(message)}")[0, 32]
    end

    # Lowercase, collapse whitespace, mask volatile tokens (UUIDs, long id/hash runs, numbers).
    def normalize_suppression_message(message)
      s = message.to_s.strip.downcase
      s = s.gsub(/\s+/, " ")
      s = s.gsub(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/, "<id>")
      s = s.gsub(/[0-9a-z]{12,}/, "<id>")
      s = s.gsub(/\b0x[0-9a-f]+\b/, "<n>")
      s = s.gsub(/\d+/, "<n>")
      (s.strip[0, 200] || "")
    end

    # Whether the dashboard has ignored this error (its suppression key is in the remote-config list).
    def error_suppressed?(exception_class, message)
      keys = remote_config["suppress"]
      return false unless keys.is_a?(Array) && !keys.empty?

      keys.include?(suppression_key(exception_class, message))
    end

    def install!
      return if defined?(@@lookout_installed) && @@lookout_installed

      @@lookout_installed = true
      @query_seq = 0

      return unless defined?(ActiveSupport::Notifications)

      store.max = max_breadcrumbs

      ActiveSupport::Notifications.subscribe("start_processing.action_controller") do |_name, _start, _finish, _id, payload|
        reset_store!
        req = payload[:request]
        method = payload[:method] || (req && req.request_method)
        path = if req && req.respond_to?(:filtered_path)
          req.filtered_path
        elsif req
          req.fullpath
        else
          payload[:path]
        end
        store.add(type: "http", category: "dispatch", level: "info", message: "#{method} #{path}") if method || path
        begin_trace!(method, path) if traces_enabled?
      end

      ActiveSupport::Notifications.subscribe("process_action.action_controller") do |_name, _start, finish, _id, payload|
        # payload[:controller] is the controller class *name* (a String), not an instance.
        cname = payload[:controller].to_s
        cname = "unknown" if cname.empty?
        action = payload[:action].to_s
        status = payload[:status]
        store.add(type: "http", category: "controller", level: "info", message: "#{cname}##{action} → #{status}")
        report_http_not_found(payload) if status.to_i == 404
        finish_trace!(payload, finish) if trace
      end

      ActiveSupport::Notifications.subscribe("perform_start.active_job") do |_name, _start, _finish, _id, payload|
        reset_store!
        job = payload[:job]
        next unless job

        jname = job.class.name
        jid = job.respond_to?(:job_id) ? job.job_id : nil
        data = {}
        data["job_id"] = jid if jid
        store.add(type: "queue", category: "job", level: "info", message: "Job started: #{jname}", data: data)
        # Open a job run (status: in_progress) for the Queues watcher.
        begin_job_run!(job) if jobs_enabled?
      end

      # perform.active_job spans the actual execution and carries payload[:exception_object] on
      # failure — close the job run (ok/error) here.
      ActiveSupport::Notifications.subscribe("perform.active_job") do |_name, _start, _finish, _id, payload|
        job = payload[:job]
        jname = job ? job.class.name : "unknown"
        store.add(type: "queue", category: "job", level: "info", message: "perform.active_job: #{jname}")
        finish_job_run!(payload) if job && job_runs.key?(job_run_key(job))
      end

      %w[enqueue.active_job discard.active_job retry_stopped.active_job].each do |ev|
        ActiveSupport::Notifications.subscribe(ev) do |_name, _start, _finish, _id, payload|
          job = payload[:job]
          jname = job ? job.class.name : "unknown"
          store.add(type: "queue", category: "job", level: "info", message: "#{ev}: #{jname}")
        end
      end

      # Subscribe to SQL when either feature wants it: breadcrumbs (LOOKOUT_INSTRUMENT_SQL, sampled)
      # and/or db.query child spans for request traces (when performance is enabled at boot).
      instrument_sql = ENV["LOOKOUT_INSTRUMENT_SQL"].to_s == "1"
      return unless instrument_sql || traces_enabled?

      ActiveSupport::Notifications.subscribe("sql.active_record") do |_name, start, finish, _id, payload|
        record_query_span(payload, start, finish) if trace

        next unless instrument_sql

        @query_seq += 1
        every = [sql_sample_every, 1].max
        next if (@query_seq % every) != 0

        sql = payload[:sql].to_s
        sql = sql[0, 500] + "…" if sql.length > 500
        store.add(
          type: "query",
          category: "db",
          level: "debug",
          message: sql,
          data: { "name" => payload[:name], "cached" => payload[:cached] }
        )
      end
    end

    def subscribe_notification(pattern)
      raise "Call LookoutFramework.install! first" unless defined?(@@lookout_installed) && @@lookout_installed

      ActiveSupport::Notifications.subscribe(pattern) do |name, _start, _finish, _id, _payload|
        store.add(type: "event", category: "notification", level: "info", message: name.to_s)
      end
    end

    def report_exception(exception)
      return if api_key.to_s.empty? || base_uri.to_s.empty?
      return unless exception.is_a?(Exception)

      msg = exception.message.to_s
      msg = exception.class.name if msg.empty?

      return if error_suppressed?(exception.class.name, msg)

      body = {
        "api_key" => api_key,
        "message" => msg,
        "exception_class" => exception.class.name,
        "stack_trace" => Array(exception.backtrace).join("\n"),
        "level" => "error",
        "language" => "ruby",
        "handled" => false,
        "breadcrumbs" => store.breadcrumbs.dup,
        "context" => { "ruby" => ruby_context }
      }

      post_ingest(body)
    rescue StandardError
      nil
    end

    def report_http_not_found(payload)
      return unless report_http_404_enabled?
      return if api_key.to_s.empty? || base_uri.to_s.empty?

      req = payload[:request]
      method = req.respond_to?(:request_method) ? req.request_method.to_s.upcase : "GET"
      path = if req.respond_to?(:fullpath)
        req.fullpath.to_s
      else
        "/"
      end
      path = "/#{path}" unless path.start_with?("/")
      url = if req.respond_to?(:original_url)
        req.original_url.to_s
      else
        "#{base_uri}#{path}"
      end

      body = {
        "api_key" => api_key,
        "message" => "HTTP 404 Not Found: #{method} #{path}",
        "exception_class" => "ActionController::RoutingError",
        "level" => "warning",
        "handled" => true,
        "language" => "ruby",
        "route" => path,
        "url" => url,
        "breadcrumbs" => store.breadcrumbs.dup,
        "context" => ruby_context.merge(
          "http" => {
            "method" => method,
            "status_code" => 404,
            "url" => url,
            "path" => path
          }
        )
      }

      return if error_suppressed?(body["exception_class"], body["message"])

      post_ingest(body)
    rescue StandardError
      nil
    end

    def report_http_404_enabled?
      ENV.fetch("LOOKOUT_REPORT_HTTP_404", "1").to_s != "0"
    end

    # Explicit dump API: capture a value (as a normalized, redacted tree) to the Lookout Dumps watcher.
    # Returns the value so it can be used inline: +user = LookoutFramework.dump(user, label: "user")+.
    def dump(value, label: nil)
      return value if api_key.to_s.empty? || base_uri.to_s.empty?
      return value unless dumps_enabled?

      result = DumpSerializer.new.serialize(value, label)
      entry = {
        "label" => label,
        "source" => "rails",
        "preview" => result["preview"],
        "root_type" => result["root_type"],
        "root_class" => result["root_class"],
        "tree" => result["tree"],
        "truncated" => result["truncated"],
        "format" => "json",
        "dumped_at" => Time.now.utc.iso8601
      }
      entry["environment"] = environment unless environment.to_s.empty?

      post_dump({ "api_key" => api_key, "entries" => [entry] }, env_forced: dumps_env_override == true)
      value
    rescue StandardError
      value
    end

    # Wrap a CLI / rake task run so it shows up in the Commands watcher. Rails has no CommandStarting
    # event the way Laravel's artisan does, so this is an explicit wrapper:
    #
    #   task :backup do
    #     LookoutFramework.command("rake backup") { do_the_work }
    #   end
    #
    # Captures a root `console.command` span (+ db.query children for SQL run inside the block) with
    # the exit code, and posts it **synchronously** to the trace ingest API — a rake process exits
    # the moment the block returns, so an off-thread post would be lost. Re-raises so the task still
    # fails; gated by the same performance signal as request traces.
    def command(name, &block)
      active = traces_enabled? && !api_key.to_s.empty? && !base_uri.to_s.empty?
      return (block ? block.call : nil) unless active

      Thread.current[:_lookout_trace] = {
        "trace_id" => SecureRandom.hex(16),
        "root_id" => SecureRandom.hex(8),
        "name" => name.to_s,
        "start" => Time.now.to_f,
        "spans" => []
      }
      exit_code = 0
      begin
        block ? block.call : nil
      rescue Exception # rubocop:disable Lint/RescueException -- record the failure, then re-raise
        exit_code = 1
        raise
      ensure
        finish_command_trace!(exit_code)
      end
    end

    def reset_store!
      store.clear
      @query_seq = 0
      Thread.current[:_lookout_trace] = nil
    end

    private

    def store
      Thread.current[:_lookout_framework_store] ||= Store.new.tap { |s| s.max = max_breadcrumbs }
    end

    # Request-scoped trace accumulator (or nil when no trace is active on this thread).
    def trace
      Thread.current[:_lookout_trace]
    end

    # Open a request trace: a root http.server span plus a buffer for child spans. We stamp epoch
    # time with Time.now (not the notification's start arg, which may be a monotonic clock value) so
    # the absolute "when" the dashboard shows is correct; child-span durations are computed from
    # event start/finish deltas, which are clock-agnostic.
    def begin_trace!(method, path)
      Thread.current[:_lookout_trace] = {
        "trace_id" => SecureRandom.hex(16),
        "root_id" => SecureRandom.hex(8),
        "method" => (method && method.to_s),
        "path" => (path && path.to_s),
        "start" => Time.now.to_f,
        "spans" => []
      }
    end

    # Append a db.query child span for an executed (non-cached) SQL statement.
    def record_query_span(payload, qstart, qfinish)
      t = trace
      return if t.nil? || payload[:cached]
      return if t["spans"].size >= trace_max_spans

      duration = begin
        d = (qfinish - qstart).to_f
        d.negative? ? 0.0 : d
      rescue StandardError
        0.0
      end
      ended = Time.now.to_f
      sql = payload[:sql].to_s
      sql = sql[0, 2000] + "…" if sql.length > 2000
      data = { "db.duration_ms" => (duration * 1000).round(3) }
      data["db.name"] = payload[:name].to_s if payload[:name]

      t["spans"] << {
        "span_id" => SecureRandom.hex(8),
        "parent_span_id" => t["root_id"],
        "op" => "db.query",
        "description" => sql,
        "start_timestamp" => ended - duration,
        "end_timestamp" => ended,
        "status" => "ok",
        "data" => data
      }
    end

    # Per-thread map of in-flight job runs, keyed by job id, holding the client-generated run_id and
    # start time so perform.active_job can close the run perform_start opened.
    def job_runs
      Thread.current[:_lookout_job_runs] ||= {}
    end

    def job_run_key(job)
      (job.respond_to?(:job_id) && job.job_id) ? job.job_id.to_s : job.object_id.to_s
    end

    # Open a job run: POST status=in_progress with a fresh client-generated run_id. Synchronous and
    # ordered before the completion event, which the server requires (it updates this row by run_id).
    def begin_job_run!(job)
      return unless job
      return if api_key.to_s.empty? || base_uri.to_s.empty?

      run_id = SecureRandom.uuid
      job_runs[job_run_key(job)] = { "run_id" => run_id, "start" => Time.now.to_f }
      post_job(job_event_body(job, "in_progress", run_id))
    rescue StandardError
      nil
    end

    # Close a job run: POST status=ok/error with the same run_id, the wall-clock duration, and the
    # exception (when the job raised).
    def finish_job_run!(payload)
      job = payload[:job]
      entry = job && job_runs.delete(job_run_key(job))
      return if entry.nil?
      return if api_key.to_s.empty? || base_uri.to_s.empty?

      exception = payload[:exception_object]
      body = job_event_body(job, exception ? "error" : "ok", entry["run_id"])
      duration = Time.now.to_f - entry["start"].to_f
      body["duration"] = duration.round(6) if duration >= 0
      if exception
        body["exception"] = {
          "class" => exception.class.name,
          "message" => exception.message.to_s[0, 1024],
          "stack" => Array(exception.backtrace).join("\n")[0, 20_000]
        }
      end
      post_job(body)
    rescue StandardError
      nil
    end

    # Shared job-event payload (omitting blanks). attempt = ActiveJob executions (1 on first try).
    def job_event_body(job, status, run_id)
      body = {
        "job" => job.class.name,
        "status" => status,
        "run_id" => run_id,
        "attempt" => job_attempt(job)
      }
      queue = (job.respond_to?(:queue_name) ? job.queue_name.to_s : "")
      body["queue"] = queue unless queue.empty?
      connection = job_connection(job)
      body["connection"] = connection if connection
      body["environment"] = environment unless environment.to_s.empty?
      body
    end

    def job_attempt(job)
      n = job.respond_to?(:executions) ? job.executions.to_i : 1
      [[n, 1].max, 255].min
    end

    def job_connection(job)
      klass = job.class
      return nil unless klass.respond_to?(:queue_adapter_name)

      name = klass.queue_adapter_name.to_s
      name.empty? ? nil : name[0, 64]
    rescue StandardError
      nil
    end

    # Close a console.command trace and post it synchronously (the CLI process exits next).
    def finish_command_trace!(exit_code)
      t = trace
      Thread.current[:_lookout_trace] = nil
      return if t.nil?
      return if api_key.to_s.empty? || base_uri.to_s.empty?

      data = { "exit_code" => exit_code.to_i }
      query_count = t["spans"].count { |s| s["op"] == "db.query" }
      data["db.query_count"] = query_count if query_count.positive?

      root = {
        "span_id" => t["root_id"],
        "parent_span_id" => nil,
        "op" => "console.command",
        "description" => t["name"],
        "start_timestamp" => t["start"],
        "end_timestamp" => Time.now.to_f,
        # The Commands watcher counts failures by status == "error" (not "internal_error").
        "status" => exit_code.to_i.zero? ? "ok" : "error",
        "data" => data
      }

      body = {
        "trace_id" => t["trace_id"],
        "transaction" => t["name"],
        "spans" => [root] + t["spans"]
      }
      body["environment"] = environment unless environment.to_s.empty?

      post_to(trace_ingest_path, body, env_forced: traces_env_override == true)
    rescue StandardError
      nil
    end

    # Close the request trace and post it (root http.server span + children) to the trace ingest API.
    def finish_trace!(payload, _finished_at)
      t = trace
      Thread.current[:_lookout_trace] = nil
      return if t.nil?
      return if api_key.to_s.empty? || base_uri.to_s.empty?
      return unless traces_enabled?

      cname = payload[:controller].to_s
      action = payload[:action].to_s
      status = payload[:status].to_i
      status = 500 if status.zero? && (payload[:exception] || payload[:exception_object])

      description = [t["method"], t["path"]].compact.join(" ").strip
      description = "#{cname}##{action}" if description.empty?

      data = {}
      data["http.method"] = t["method"] if t["method"]
      data["http.route"] = cname.empty? ? t["path"] : "#{cname}##{action}"
      data["http.status_code"] = status if status.positive?
      query_count = t["spans"].count { |s| s["op"] == "db.query" }
      data["db.query_count"] = query_count if query_count.positive?

      root = {
        "span_id" => t["root_id"],
        "parent_span_id" => nil,
        "op" => "http.server",
        "description" => description,
        "start_timestamp" => t["start"],
        "end_timestamp" => Time.now.to_f,
        "status" => status >= 500 ? "internal_error" : "ok",
        "data" => data
      }

      body = {
        "trace_id" => t["trace_id"],
        "transaction" => description,
        "spans" => [root] + t["spans"]
      }
      body["environment"] = environment unless environment.to_s.empty?

      post_trace(body, env_forced: traces_env_override == true)
    rescue StandardError
      nil
    end

    def ruby_context
      {
        "ruby_version" => RUBY_VERSION,
        "rails_version" => (Rails.version if defined?(Rails))
      }.compact
    end

    def post_ingest(body)
      post_to(ingest_path, body)
    end

    def post_dump(body, env_forced: false)
      post_to(dump_ingest_path, body, env_forced: env_forced)
    end

    # Traces fire on every request, so post off-thread to keep tracing off the response's critical
    # path. Best-effort: failures are swallowed like the other signals.
    def post_trace(body, env_forced: false)
      Thread.new do
        post_to(trace_ingest_path, body, env_forced: env_forced)
      rescue StandardError
        nil
      end
    end

    # Job runs post synchronously: the completion event must reach the server *after* its in_progress
    # row exists (the server updates by run_id), and jobs run off the request path so latency is fine.
    def post_job(body, env_forced: jobs_env_override == true)
      post_to(job_ingest_path, body, env_forced: env_forced)
    end

    def post_to(path, body, env_forced: false)
      path = "/#{path}" unless path.start_with?("/")
      uri = URI.parse("#{base_uri}#{path}")
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == "https"
      http.open_timeout = 2
      http.read_timeout = 5
      req = Net::HTTP::Post.new(uri.request_uri)
      req["Content-Type"] = "application/json"
      req["Accept"] = "application/json"
      req["X-Api-Key"] = api_key
      # env > site: tell the server this signal is force-enabled by the app's env so it accepts
      # the request even when the dashboard toggle is off.
      req["X-Lookout-Env-Forced"] = "1" if env_forced
      req.body = JSON.generate(body)
      http.request(req)
    end

    def fetch_remote_config
      return nil if api_key.to_s.empty? || base_uri.to_s.empty?

      uri = URI.parse("#{base_uri}/api/config")
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == "https"
      http.open_timeout = 2
      http.read_timeout = 5
      req = Net::HTTP::Get.new(uri.request_uri)
      req["Accept"] = "application/json"
      req["X-Api-Key"] = api_key
      report = env_overrides_report
      req["X-Lookout-Env-Overrides"] = report if report

      res = http.request(req)
      return nil unless res.is_a?(Net::HTTPSuccess)

      data = JSON.parse(res.body)
      data.is_a?(Hash) ? data : nil
    rescue StandardError
      nil
    end

    # Base64(JSON) of this app's explicit env signal overrides for the X-Lookout-Env-Overrides
    # report header, or nil when nothing is pinned by env.
    def env_overrides_report
      overrides = {}
      dumps = dumps_env_override
      overrides["dumps"] = { "enabled" => dumps } unless dumps.nil?
      traces = traces_env_override
      overrides["traces"] = { "enabled" => traces } unless traces.nil?
      jobs = jobs_env_override
      overrides["jobs"] = { "enabled" => jobs } unless jobs.nil?
      return nil if overrides.empty?

      Base64.strict_encode64(JSON.generate(overrides))
    end
  end
end
