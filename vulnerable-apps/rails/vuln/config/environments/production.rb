Rails.application.configure do
  config.cache_classes = true
  config.eager_load = false
  config.consider_all_requests_local = true
  config.public_file_server.enabled = true
  config.log_level = ENV.fetch("RAILS_LOG_LEVEL", "info")
  config.secret_key_base = ENV.fetch("SECRET_KEY_BASE", "rails-hardcoded-secret-key-base-000000000000000000000000000000") # VULN SECRET-001: hardcoded fallback signs cookies
end
