require_relative "boot"
require "rails/all"
Bundler.require(*Rails.groups)

module RailsBenchApp
  class Application < Rails::Application
    config.load_defaults 7.2
    config.eager_load = false
    config.active_record.schema_format = :ruby
    config.hosts.clear
    config.public_file_server.enabled = true
    config.middleware.insert_before 0, Rack::Cors do
      allow do
        origins { |source, _env| source } # VULN CORS-001: reflect arbitrary Origin with credentials
        resource "*", headers: :any, methods: [:get, :post, :patch, :put, :delete, :options], credentials: true
      end
    end
  end
end
