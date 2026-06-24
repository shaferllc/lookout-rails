# frozen_string_literal: true

# Copy into config/initializers/lookout_framework.rb (or lib/) and call LookoutFramework.install!
# See packages/lookout-rails/README.md

require "base64"
require "digest"
require "json"
require "logger"
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

  # Opt-in logger that mirrors Rails.logger writes into LookoutFramework.log. Attached to the
  # broadcast logger so existing logging is unchanged; a thread-local guard prevents the SDK's own
  # logging from re-entering and looping.
  class LogForwarder < ::Logger
    SEVERITIES = { 0 => "debug", 1 => "info", 2 => "warn", 3 => "error", 4 => "fatal", 5 => "info" }.freeze

    def initialize(min_level)
      super(File::NULL)
      self.level = min_level
    end

    def add(severity, message = nil, progname = nil)
      sev = severity || UNKNOWN
      return true if sev < level
      return true if Thread.current[:_lookout_in_log]

      Thread.current[:_lookout_in_log] = true
      begin
        text = (message || (block_given? ? yield : progname)).to_s
        LookoutFramework.log(SEVERITIES.fetch(sev, "info"), text, logger: (message.nil? ? nil : progname&.to_s))
      ensure
        Thread.current[:_lookout_in_log] = false
      end
      true
    end
  end

  # Mixed into ActiveRecord::Base so create/update/destroy feed the Models watcher.
  module ModelTracking
    def self.included(base)
      base.after_create  { LookoutFramework.send(:record_model_change, self, "created") }
      base.after_update  { LookoutFramework.send(:record_model_change, self, "updated") }
      base.after_destroy { LookoutFramework.send(:record_model_change, self, "deleted") }
    end
  end

  # Prepended to Net::HTTP (opt-in) so outbound requests become http.client spans on the active trace.
  module HttpInstrumentation
    def request(req, body = nil, &block)
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      response = super
      LookoutFramework.send(:record_http_span, self, req, response, started)
      response
    rescue StandardError => e
      begin
        LookoutFramework.send(:record_http_span, self, req, nil, started, e)
      rescue StandardError
        nil
      end
      raise
    end
  end

  # Registered as a redis-client middleware (opt-in) so commands become db.redis spans.
  module RedisInstrumentation
    def call(command, redis_config)
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      super
    ensure
      begin
        LookoutFramework.send(:record_redis_span, command, started)
      rescue StandardError
        nil
      end
    end

    def call_pipelined(commands, redis_config)
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      super
    ensure
      begin
        Array(commands).each { |c| LookoutFramework.send(:record_redis_span, c, started) }
      rescue StandardError
        nil
      end
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

    def log_ingest_path
      @log_ingest_path ||= ENV.fetch("LOOKOUT_LOG_INGEST_PATH", "/api/ingest/log")
    end

    def mail_ingest_path
      @mail_ingest_path ||= ENV.fetch("LOOKOUT_MAIL_INGEST_PATH", "/api/ingest/mail")
    end

    def batch_ingest_path
      @batch_ingest_path ||= ENV.fetch("LOOKOUT_BATCH_INGEST_PATH", "/api/ingest/batch")
    end

    # Buffered batch signals share one transport (POST {path} {entries:[...]}). Each maps to its
    # ingest path, its LOOKOUT_<X>_ENABLED env override, and its GET /api/config signal key.
    BATCH_SIGNALS = {
      "models" => { path: "/api/ingest/model", env: "LOOKOUT_MODELS_ENABLED", key: "models" },
      "events" => { path: "/api/ingest/event", env: "LOOKOUT_EVENTS_ENABLED", key: "events" },
      "gates" => { path: "/api/ingest/gate", env: "LOOKOUT_GATES_ENABLED", key: "gates" },
      "metrics" => { path: "/api/ingest/metric", env: "LOOKOUT_METRICS_ENABLED", key: "metrics" }
    }.freeze

    # Flush the log buffer once it reaches this many entries (server caps a batch at 200).
    def logs_max_buffer
      @logs_max_buffer ||= [[ENV.fetch("LOOKOUT_LOGS_MAX_BUFFER", "50").to_i, 1].max, 200].min
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

    # Explicit env override for the logs signal, or nil when unset (env > site).
    def logs_env_override
      raw = ENV["LOOKOUT_LOGS_ENABLED"]
      return nil if raw.nil? || raw.to_s.strip.empty?

      %w[1 true yes on].include?(raw.to_s.strip.downcase)
    end

    # Whether to forward log records to the Logs watcher. Defaults OFF (opt-in like the other
    # optional signals): LOOKOUT_LOGS_ENABLED=1 (force-accepts via X-Lookout-Env-Forced) or the
    # dashboard signal.
    def logs_enabled?
      override = logs_env_override
      return override unless override.nil?

      !!remote_config.dig("signals", "logs", "enabled")
    end

    # Explicit env override for the mail signal, or nil when unset (env > site).
    def mail_env_override
      raw = ENV["LOOKOUT_MAIL_ENABLED"]
      return nil if raw.nil? || raw.to_s.strip.empty?

      %w[1 true yes on].include?(raw.to_s.strip.downcase)
    end

    # Whether to report sent mail (ActionMailer) to the Mail watcher. Opt-in (defaults OFF).
    def mail_enabled?
      override = mail_env_override
      return override unless override.nil?

      !!remote_config.dig("signals", "mail", "enabled")
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
        flush_logs!(async: true)
        flush_all_signals!(async: true)
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
        flush_logs!
        flush_all_signals!
      end

      %w[enqueue.active_job discard.active_job retry_stopped.active_job].each do |ev|
        ActiveSupport::Notifications.subscribe(ev) do |_name, _start, _finish, _id, payload|
          job = payload[:job]
          jname = job ? job.class.name : "unknown"
          store.add(type: "queue", category: "job", level: "info", message: "#{ev}: #{jname}")
        end
      end

      # ActionMailer → Mail watcher (one record per delivered message).
      ActiveSupport::Notifications.subscribe("deliver.action_mailer") do |_name, _start, _finish, _id, payload|
        report_mail(payload) if mail_enabled?
      end

      # ActiveRecord create/update/destroy → Models watcher (buffered, batched).
      if signal_on?("models") && defined?(ActiveSupport)
        ActiveSupport.on_load(:active_record) do
          include LookoutFramework::ModelTracking
        end
      end

      # Drain any buffered signals when the process exits (covers short-lived CLI/rake runs).
      at_exit do
        flush_logs!
        flush_all_signals!
      end

      # Opt-in: mirror Rails.logger output to the Logs watcher (LOOKOUT_FORWARD_RAILS_LOG=1).
      attach_log_forwarder! if forward_rails_log?

      # Rails.cache reads/writes/deletes → cache.* child spans → Cache watcher (needs perf at boot).
      # Rails ≥ 5.2 always emits cache_* notifications (the old Cache::Store.instrument flag is gone).
      if traces_enabled?
        ActiveSupport::Notifications.subscribe("cache_read.active_support") do |_n, qs, qf, _i, payload|
          record_cache_span("cache.get", qs, qf, payload, payload[:hit] ? "hit" : "miss", payload[:hit])
        end
        ActiveSupport::Notifications.subscribe("cache_write.active_support") do |_n, qs, qf, _i, payload|
          record_cache_span("cache.set", qs, qf, payload, "ok", nil)
        end
        ActiveSupport::Notifications.subscribe("cache_delete.active_support") do |_n, qs, qf, _i, payload|
          record_cache_span("cache.remove", qs, qf, payload, "ok", nil)
        end
      end

      # Opt-in outbound-HTTP + Redis instrumentation (no standard ActiveSupport events for these).
      instrument_http! if env_flag("LOOKOUT_INSTRUMENT_HTTP")
      instrument_redis! if env_flag("LOOKOUT_INSTRUMENT_REDIS")

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
        flush_logs!
        flush_all_signals!
      end
    end

    # Forward a structured log record to the Logs watcher. Buffered and flushed in batches (at request
    # / job / command end, at process exit, or when the buffer fills). attributes is an optional Hash.
    #
    #   LookoutFramework.log(:warn, "Payment retry", attempt: 2, order_id: 17)
    def log(level, message, attributes = nil, logger: nil)
      return unless logs_enabled?
      return if api_key.to_s.empty? || base_uri.to_s.empty?

      entry = {
        "level" => normalize_log_level(level),
        "message" => message.to_s[0, 262_144],
        "source" => "ruby",
        "logger" => (logger || "rails").to_s[0, 128],
        "timestamp" => Time.now.to_f
      }
      entry["environment"] = environment unless environment.to_s.empty?
      active = trace
      entry["trace_id"] = active["trace_id"] if active && active["trace_id"]
      attrs = log_attributes(attributes)
      entry["attributes"] = attrs if attrs

      size = nil
      log_mutex.synchronize do
        log_buffer << entry
        size = log_buffer.size
      end
      flush_logs!(async: true) if size >= logs_max_buffer
      nil
    rescue StandardError
      nil
    end

    # Post any buffered log entries to the log ingest API (in chunks of 200). async: post off-thread
    # (used on the web request path); synchronous flushes are used at job/command end and at exit.
    def flush_logs!(async: false)
      batch = nil
      log_mutex.synchronize do
        return nil if log_buffer.empty?

        batch = log_buffer.slice!(0, log_buffer.length)
      end
      return nil if api_key.to_s.empty? || base_uri.to_s.empty?

      poster = lambda do
        batch.each_slice(200) do |chunk|
          post_to(log_ingest_path, { "entries" => chunk }, env_forced: logs_env_override == true)
        rescue StandardError
          nil
        end
      end
      async ? Thread.new { poster.call } : poster.call
      nil
    rescue StandardError
      nil
    end

    # Record a custom domain event → Events watcher.
    def event(name, listeners: nil, broadcast: false, meta: nil)
      return unless signal_on?("events")

      entry = { "event" => name.to_s[0, 512], "broadcast" => !!broadcast, "dispatched_at" => Time.now.utc.iso8601 }
      entry["listeners"] = [[listeners.to_i, 0].max, 65_535].min unless listeners.nil?
      entry["meta"] = stringify_keys(meta) if meta.is_a?(Hash) && meta.any?
      enqueue_signal("events", with_common(entry))
      nil
    end

    # Record an authorization gate / feature-flag check → Gates watcher. Returns `allowed`.
    def gate(ability, allowed:, user: nil, target: nil, meta: nil)
      return allowed unless signal_on?("gates")

      entry = { "ability" => ability.to_s[0, 255], "result" => (allowed ? "allowed" : "denied"), "occurred_at" => Time.now.utc.iso8601 }
      entry["target"] = target.to_s[0, 512] unless target.nil?
      entry["user"] = user.to_s[0, 64] unless user.nil?
      entry["meta"] = stringify_keys(meta) if meta.is_a?(Hash) && meta.any?
      enqueue_signal("gates", with_common(entry))
      allowed
    end

    # Record a custom metric sample → Metrics watcher. kind: counter | gauge | distribution.
    def metric(name, value, kind: "gauge", unit: nil, attributes: nil)
      return value unless signal_on?("metrics")
      return value unless value.respond_to?(:to_f) && value.to_f.finite?

      entry = { "name" => name.to_s[0, 128], "kind" => normalize_metric_kind(kind), "value" => value.to_f, "timestamp" => Time.now.to_f }
      entry["unit"] = unit.to_s[0, 32] unless unit.nil?
      entry["attributes"] = stringify_keys(attributes) if attributes.is_a?(Hash) && attributes.any?
      enqueue_signal("metrics", with_common(entry))
      value
    end

    def count(name, delta = 1, unit: nil, attributes: nil)
      metric(name, delta, kind: "counter", unit: unit, attributes: attributes)
    end

    def gauge(name, value, unit: nil, attributes: nil)
      metric(name, value, kind: "gauge", unit: unit, attributes: attributes)
    end

    def distribution(name, value, unit: nil, attributes: nil)
      metric(name, value, kind: "distribution", unit: unit, attributes: attributes)
    end

    # Upsert job-batch progress → Batches watcher (server keys by batch_id; send the same id as it
    # progresses). Status/progress are derived server-side from the job counts + finished/cancelled.
    def batch(batch_id, name: nil, total_jobs: nil, pending_jobs: nil, failed_jobs: nil, status: nil, finished_at: nil, cancelled_at: nil, meta: nil)
      return if batch_id.to_s.empty?
      return unless batches_enabled?
      return if api_key.to_s.empty? || base_uri.to_s.empty?

      entry = { "batch_id" => batch_id.to_s[0, 64] }
      entry["name"] = name.to_s[0, 255] unless name.nil?
      entry["total_jobs"] = total_jobs.to_i unless total_jobs.nil?
      entry["pending_jobs"] = pending_jobs.to_i unless pending_jobs.nil?
      entry["failed_jobs"] = failed_jobs.to_i unless failed_jobs.nil?
      entry["status"] = status.to_s unless status.nil?
      entry["finished_at"] = iso_time(finished_at) unless finished_at.nil?
      entry["cancelled_at"] = iso_time(cancelled_at) unless cancelled_at.nil?
      entry["meta"] = stringify_keys(meta) if meta.is_a?(Hash) && meta.any?
      with_common(entry)
      forced = env_flag("LOOKOUT_BATCHES_ENABLED") == true
      Thread.new do
        post_to(batch_ingest_path, entry, env_forced: forced)
      rescue StandardError
        nil
      end
      nil
    end

    # Monitor a scheduled task → Cron watcher. Two-phase check-in (in_progress → ok/error) around the
    # block, posted synchronously. Re-raises so the task still fails.
    def cron(slug, &block)
      active = cron_enabled? && !api_key.to_s.empty? && !base_uri.to_s.empty?
      return (block ? block.call : nil) unless active

      check_in_id = SecureRandom.uuid
      started = Time.now.to_f
      post_cron(slug, "in_progress", check_in_id)
      begin
        result = block ? block.call : nil
        post_cron(slug, "ok", check_in_id, Time.now.to_f - started)
        result
      rescue Exception # rubocop:disable Lint/RescueException -- record failure then re-raise
        post_cron(slug, "error", check_in_id, Time.now.to_f - started)
        raise
      end
    end

    # Attach user feedback to an error occurrence → User Feedback watcher. Pass the occurrence_uuid or
    # error event_id the feedback is about (one of them is required by the server).
    def user_feedback(comments:, occurrence_uuid: nil, event_id: nil, name: nil, email: nil)
      return if comments.to_s.strip.empty?
      return unless feedback_enabled?
      return if api_key.to_s.empty? || base_uri.to_s.empty?

      body = { "comments" => comments.to_s[0, 10_000] }
      if !occurrence_uuid.to_s.empty?
        body["occurrence_uuid"] = occurrence_uuid.to_s
      elsif !event_id.to_s.empty?
        body["event_id"] = event_id.to_s
      end
      body["name"] = name.to_s[0, 128] unless name.nil?
      body["email"] = email.to_s[0, 255] unless email.nil?
      forced = env_flag("LOOKOUT_FEEDBACK_ENABLED") == true
      Thread.new do
        post_to(feedback_ingest_path, body, env_forced: forced)
      rescue StandardError
        nil
      end
      nil
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
      # The Queries watcher's default (aggregate) view groups by db.statement_fingerprint and skips
      # spans without one, so always provide a normalized fingerprint.
      data["db.statement_fingerprint"] = sql_fingerprint(payload[:sql].to_s)

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

    # Append a cache.* child span (Cache watcher). result is hit/miss/ok; hit is the bool the miss
    # stat keys off (nil for writes/deletes).
    def record_cache_span(op, qstart, qfinish, payload, result, hit)
      t = trace
      return if t.nil? || t["spans"].size >= trace_max_spans

      duration = span_duration(qstart, qfinish)
      ended = Time.now.to_f
      data = { "cache.result" => result, "cache.duration_ms" => (duration * 1000).round(3) }
      data["cache.hit"] = !!hit unless hit.nil?
      data["cache.key"] = payload[:key].to_s[0, 200] if payload[:key]
      data["cache.store"] = payload[:store].to_s if payload[:store]
      t["spans"] << {
        "span_id" => SecureRandom.hex(8),
        "parent_span_id" => t["root_id"],
        "op" => op,
        "description" => "#{op} #{payload[:key]}".strip[0, 512],
        "start_timestamp" => ended - duration,
        "end_timestamp" => ended,
        "status" => "ok",
        "data" => data
      }
    end

    # Append an http.client child span (HTTP Client watcher) for an outbound Net::HTTP request.
    # Skips calls to our own ingest host so the SDK never traces itself.
    def record_http_span(http, request, response, started_mono, error = nil)
      t = trace
      return if t.nil? || t["spans"].size >= trace_max_spans

      host = http.address.to_s
      return if host.empty? || host == ingest_host

      duration = [Process.clock_gettime(Process::CLOCK_MONOTONIC) - started_mono, 0.0].max
      ended = Time.now.to_f
      scheme = http.respond_to?(:use_ssl?) && http.use_ssl? ? "https" : "http"
      method = request.respond_to?(:method) ? request.method.to_s : "GET"
      path = request.respond_to?(:path) ? request.path.to_s : "/"
      status = response.respond_to?(:code) ? response.code.to_i : nil
      data = { "server.address" => host[0, 255] }
      data["http.status_code"] = status if status&.positive?
      data["error"] = error.message.to_s[0, 500] if error
      t["spans"] << {
        "span_id" => SecureRandom.hex(8),
        "parent_span_id" => t["root_id"],
        "op" => "http.client",
        "description" => "#{method} #{scheme}://#{host}#{path}"[0, 512],
        "start_timestamp" => ended - duration,
        "end_timestamp" => ended,
        "status" => (error || (status && status >= 500)) ? "internal_error" : "ok",
        "data" => data
      }
    end

    # Append a db.redis child span (Redis watcher) for a redis-client command.
    def record_redis_span(command, started_mono)
      t = trace
      return if t.nil? || t["spans"].size >= trace_max_spans

      duration = [Process.clock_gettime(Process::CLOCK_MONOTONIC) - started_mono, 0.0].max
      ended = Time.now.to_f
      verb = Array(command).first.to_s.upcase[0, 64]
      t["spans"] << {
        "span_id" => SecureRandom.hex(8),
        "parent_span_id" => t["root_id"],
        "op" => "db.redis",
        "description" => verb,
        "start_timestamp" => ended - duration,
        "end_timestamp" => ended,
        "status" => "ok",
        "data" => { "db.system" => "redis", "db.duration_ms" => (duration * 1000).round(3) }
      }
    end

    def span_duration(qstart, qfinish)
      d = (qfinish - qstart).to_f
      d.negative? ? 0.0 : d
    rescue StandardError
      0.0
    end

    # Host of the Lookout ingest base_uri, so HTTP instrumentation can skip the SDK's own calls.
    def ingest_host
      @ingest_host ||= (URI.parse(base_uri).host.to_s if base_uri.to_s != "")
    rescue StandardError
      nil
    end

    def instrument_http!
      require "net/http"
      Net::HTTP.prepend(HttpInstrumentation) unless Net::HTTP.ancestors.include?(HttpInstrumentation)
    rescue StandardError
      nil
    end

    def instrument_redis!
      return unless defined?(RedisClient) && RedisClient.respond_to?(:register)

      RedisClient.register(RedisInstrumentation)
    rescue StandardError
      nil
    end

    # Normalize a SQL statement into a stable grouping key for the Queries watcher: collapse
    # whitespace, mask string literals and numbers, and fold repeated bind placeholders.
    def sql_fingerprint(sql)
      s = sql.to_s.gsub(/\s+/, " ").strip
      s = s.gsub(/'(?:[^']|'')*'/, "?")        # single-quoted string literals (keep "identifiers")
      s = s.gsub(/\b\d+\.\d+\b/, "?")          # floats
      s = s.gsub(/\b\d+\b/, "?")               # integers
      s = s.gsub(/\?(?:\s*,\s*\?)+/, "?")      # collapse "?, ?, ?" lists
      s[0, 512]
    end

    def forward_rails_log?
      %w[1 true yes on].include?(ENV["LOOKOUT_FORWARD_RAILS_LOG"].to_s.strip.downcase)
    end

    # Minimum Ruby Logger severity to forward (default WARN to avoid flooding the Logs watcher with
    # dev info/SQL chatter). Accepts a name (debug/info/warn/error/fatal).
    def log_forward_min_level
      name = ENV.fetch("LOOKOUT_FORWARD_RAILS_LOG_LEVEL", "warn").to_s.strip.downcase
      { "debug" => Logger::DEBUG, "info" => Logger::INFO, "warn" => Logger::WARN,
        "error" => Logger::ERROR, "fatal" => Logger::FATAL }.fetch(name, Logger::WARN)
    end

    def attach_log_forwarder!
      return unless defined?(Rails) && Rails.respond_to?(:logger) && Rails.logger

      forwarder = LogForwarder.new(log_forward_min_level)
      if Rails.logger.respond_to?(:broadcast_to)
        Rails.logger.broadcast_to(forwarder)
      elsif defined?(ActiveSupport::Logger) && ActiveSupport::Logger.respond_to?(:broadcast)
        Rails.logger.extend(ActiveSupport::Logger.broadcast(forwarder))
      end
    rescue StandardError
      nil
    end

    # Process-wide log buffer (logs originate on many Puma/job threads), guarded by a mutex.
    def log_buffer
      @log_buffer ||= []
    end

    def log_mutex
      @log_mutex ||= Mutex.new
    end

    # Normalize to the server's level vocabulary (mirrors the PHP/Monolog handler).
    def normalize_log_level(level)
      l = level.to_s.strip.downcase
      l = "info" if l == "notice"
      l = "warn" if l == "warning"
      l = "fatal" if %w[critical alert emergency].include?(l)
      l = "info" if l.empty?
      l[0, 32]
    end

    # Coerce a context Hash into the server's attribute shape: <=64 keys, scalar/null kept as-is,
    # everything else JSON-encoded.
    def log_attributes(attributes)
      return nil unless attributes.is_a?(Hash) && attributes.any?

      out = {}
      attributes.first(64).each do |key, value|
        k = key.to_s[0, 128]
        out[k] = if value.is_a?(String) || value.is_a?(Numeric) || value == true || value == false || value.nil?
          value
        else
          begin
            JSON.generate(value)[0, 8192]
          rescue StandardError
            value.to_s[0, 8192]
          end
        end
      end
      out.empty? ? nil : out
    end

    # --- Generic signal gating + buffered batch transport (models/events/gates/metrics) ---------

    # Parse a boolean-ish env var to true/false, or nil when unset.
    def env_flag(name)
      raw = ENV[name]
      return nil if raw.nil? || raw.to_s.strip.empty?

      %w[1 true yes on].include?(raw.to_s.strip.downcase)
    end

    # env override (env > site) else the dashboard remote-config signal.
    def signal_enabled?(env_name, config_key)
      override = env_flag(env_name)
      return override unless override.nil?

      !!remote_config.dig("signals", config_key, "enabled")
    end

    def signal_on?(name)
      spec = BATCH_SIGNALS[name]
      spec && signal_enabled?(spec[:env], spec[:key])
    end

    def cron_enabled?
      signal_enabled?("LOOKOUT_CRON_ENABLED", "crons")
    end

    def batches_enabled?
      signal_enabled?("LOOKOUT_BATCHES_ENABLED", "batches")
    end

    def feedback_enabled?
      signal_enabled?("LOOKOUT_FEEDBACK_ENABLED", "feedback")
    end

    def cron_ingest_path
      @cron_ingest_path ||= ENV.fetch("LOOKOUT_CRON_INGEST_PATH", "/api/ingest/cron")
    end

    def feedback_ingest_path
      @feedback_ingest_path ||= ENV.fetch("LOOKOUT_FEEDBACK_INGEST_PATH", "/api/ingest/feedback")
    end

    def signal_buffers
      @signal_buffers ||= {}
    end

    def signals_mutex
      @signals_mutex ||= Mutex.new
    end

    # Attach the fields every signal shares: environment + the active request/command trace_id.
    def with_common(entry)
      entry["environment"] = environment unless environment.to_s.empty?
      active = trace
      entry["trace_id"] = active["trace_id"] if active && active["trace_id"]
      entry
    end

    def enqueue_signal(name, entry)
      return if api_key.to_s.empty? || base_uri.to_s.empty?

      size = nil
      signals_mutex.synchronize do
        (signal_buffers[name] ||= []) << entry
        size = signal_buffers[name].size
      end
      flush_signal(name, async: true) if size >= 100
    rescue StandardError
      nil
    end

    def flush_signal(name, async: false)
      spec = BATCH_SIGNALS[name]
      return unless spec

      batch = nil
      signals_mutex.synchronize do
        buf = signal_buffers[name]
        return if buf.nil? || buf.empty?

        batch = buf.slice!(0, buf.length)
      end
      return if api_key.to_s.empty? || base_uri.to_s.empty?

      forced = env_flag(spec[:env]) == true
      poster = lambda do
        batch.each_slice(100) do |chunk|
          post_to(spec[:path], { "entries" => chunk }, env_forced: forced)
        rescue StandardError
          nil
        end
      end
      async ? Thread.new { poster.call } : poster.call
    rescue StandardError
      nil
    end

    def flush_all_signals!(async: false)
      BATCH_SIGNALS.each_key { |name| flush_signal(name, async: async) }
    end

    # Build + buffer a Models-watcher entry for an ActiveRecord create/update/destroy.
    def record_model_change(model, action)
      return unless signal_on?("models")

      name = model.class.name.to_s
      return if name.empty? || name.start_with?("ActiveRecord::", "ActiveStorage::")

      entry = { "model" => name[0, 512], "change" => action, "occurred_at" => Time.now.utc.iso8601 }
      entry["key"] = model.id.to_s[0, 64] if model.respond_to?(:id) && !model.id.nil?
      if action == "updated" && model.respond_to?(:saved_changes)
        changed = (model.saved_changes.keys - %w[created_at updated_at]).first(32).map { |k| k.to_s[0, 128] }
        entry["changes"] = changed unless changed.empty?
      end
      enqueue_signal("models", with_common(entry))
    rescue StandardError
      nil
    end

    # Build + post a Mail-watcher record from a deliver.action_mailer payload (off-thread).
    def report_mail(payload)
      return if api_key.to_s.empty? || base_uri.to_s.empty?

      entry = { "mailable" => (payload[:mailer] || "ActionMailer").to_s[0, 512], "meta" => { "status" => "sent" } }
      entry["subject"] = payload[:subject].to_s[0, 512] unless payload[:subject].nil?
      recipients = Array(payload[:to]).map { |addr| addr.to_s[0, 320] }.reject(&:empty?).first(20)
      entry["to"] = recipients unless recipients.empty?
      entry["sent_at"] = iso_time(payload[:date]) || Time.now.utc.iso8601
      with_common(entry)
      forced = mail_env_override == true
      Thread.new do
        post_to(mail_ingest_path, entry, env_forced: forced)
      rescue StandardError
        nil
      end
    rescue StandardError
      nil
    end

    # Post a single cron check-in synchronously (CLI processes exit promptly; two-phase ordering).
    def post_cron(slug, status, check_in_id, duration = nil)
      body = { "slug" => slug.to_s[0, 128], "status" => status, "check_in_id" => check_in_id }
      body["duration"] = duration.round(3) if duration && duration >= 0
      body["environment"] = environment unless environment.to_s.empty?
      post_to(cron_ingest_path, body, env_forced: env_flag("LOOKOUT_CRON_ENABLED") == true)
    rescue StandardError
      nil
    end

    def normalize_metric_kind(kind)
      k = kind.to_s.strip.downcase
      %w[counter gauge distribution].include?(k) ? k : "gauge"
    end

    # The server expects string-keyed attribute/meta objects; user hashes may use symbols.
    def stringify_keys(hash)
      hash.each_with_object({}) { |(k, v), out| out[k.to_s] = v }
    end

    # Coerce a Time/Date/ISO-string to an ISO8601 UTC string, or nil.
    def iso_time(value)
      return nil if value.nil?
      return value.utc.iso8601 if value.respond_to?(:utc)

      Time.parse(value.to_s).utc.iso8601
    rescue StandardError
      nil
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
      logs = logs_env_override
      overrides["logs"] = { "enabled" => logs } unless logs.nil?
      {
        "mail" => "LOOKOUT_MAIL_ENABLED", "models" => "LOOKOUT_MODELS_ENABLED",
        "events" => "LOOKOUT_EVENTS_ENABLED", "gates" => "LOOKOUT_GATES_ENABLED",
        "metrics" => "LOOKOUT_METRICS_ENABLED", "crons" => "LOOKOUT_CRON_ENABLED",
        "batches" => "LOOKOUT_BATCHES_ENABLED", "feedback" => "LOOKOUT_FEEDBACK_ENABLED"
      }.each do |key, env_name|
        flag = env_flag(env_name)
        overrides[key] = { "enabled" => flag } unless flag.nil?
      end
      return nil if overrides.empty?

      Base64.strict_encode64(JSON.generate(overrides))
    end
  end
end
