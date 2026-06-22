# frozen_string_literal: true

# Copy into config/initializers/lookout_framework.rb (or lib/) and call LookoutFramework.install!
# See packages/lookout-rails/README.md

require "json"
require "net/http"
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

    def environment
      @environment ||= ENV["LOOKOUT_ENVIRONMENT"]
    end

    def max_breadcrumbs
      @max_breadcrumbs ||= ENV.fetch("LOOKOUT_BREADCRUMBS_MAX", "50").to_i
    end

    def sql_sample_every
      @sql_sample_every ||= ENV.fetch("LOOKOUT_INSTRUMENT_DATABASE_SAMPLE_EVERY", "5").to_i
    end

    def install!
      return if defined?(@@lookout_installed) && @@lookout_installed

      @@lookout_installed = true
      @query_seq = 0

      return unless defined?(ActiveSupport::Notifications)

      store.max = max_breadcrumbs

      ActiveSupport::Notifications.subscribe("start_processing.action_dispatch") do |_name, _start, _finish, _id, payload|
        reset_store!
        req = payload[:request]
        if req
          path = req.respond_to?(:filtered_path) ? req.filtered_path : req.fullpath
          method = req.request_method
          store.add(type: "http", category: "dispatch", level: "info", message: "#{method} #{path}")
        end
      end

      ActiveSupport::Notifications.subscribe("process_action.action_controller") do |_name, _start, _finish, _id, payload|
        ctrl = payload[:controller]
        cname = ctrl.respond_to?(:class) ? ctrl.class.name : "unknown"
        action = payload[:action].to_s
        status = payload[:status]
        store.add(type: "http", category: "controller", level: "info", message: "#{cname}##{action} → #{status}")
        report_http_not_found(payload) if status.to_i == 404
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
      end

      %w[perform.active_job enqueue.active_job discard.active_job retry_stopped.active_job].each do |ev|
        ActiveSupport::Notifications.subscribe(ev) do |_name, _start, _finish, _id, payload|
          job = payload[:job]
          jname = job ? job.class.name : "unknown"
          store.add(type: "queue", category: "job", level: "info", message: "#{ev}: #{jname}")
        end
      end

      return unless ENV["LOOKOUT_INSTRUMENT_SQL"].to_s == "1"

      ActiveSupport::Notifications.subscribe("sql.active_record") do |_name, _start, _finish, _id, payload|
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

      post_dump("api_key" => api_key, "entries" => [entry])
      value
    rescue StandardError
      value
    end

    def reset_store!
      store.clear
      @query_seq = 0
    end

    private

    def store
      Thread.current[:_lookout_framework_store] ||= Store.new.tap { |s| s.max = max_breadcrumbs }
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

    def post_dump(body)
      post_to(dump_ingest_path, body)
    end

    def post_to(path, body)
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
      req.body = JSON.generate(body)
      http.request(req)
    end
  end
end
