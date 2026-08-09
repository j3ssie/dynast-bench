Rails.application.configure do
  config.cache_classes = true
  config.eager_load = false
  config.consider_all_requests_local = true
  config.public_file_server.enabled = true
  config.log_level = ENV.fetch("RAILS_LOG_LEVEL", "info")
  config.secret_key_base = ENV.fetch("SECRET_KEY_BASE") # SAFE SECRET-001: require deployment-provided secret_key_base
end
