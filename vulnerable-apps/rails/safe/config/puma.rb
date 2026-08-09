port ENV.fetch("PORT", 3000)
environment ENV.fetch("RAILS_ENV", "production")
threads 5, 5
workers 0
pidfile ENV.fetch("PIDFILE", "tmp/pids/server.pid")
