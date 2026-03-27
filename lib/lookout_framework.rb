# frozen_string_literal: true

# Copy into config/initializers/lookout_framework.rb (or lib/) and call LookoutFramework.install!
# See packages/lookout-rails/README.md

require "json"
require "net/http"
require "uri"

module LookoutFramework
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
      path = ingest_path
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
