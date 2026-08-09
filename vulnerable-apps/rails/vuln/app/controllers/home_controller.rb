class HomeController < ApplicationController
  def index
    @public_message = "TaskFlow Rails demo"
    @leaked_secret = "rails-hardcoded-secret-key-base-000000000000000000000000000000" # VULN SECRET-001: hardcoded secret rendered to clients
    @default_creds = "admin/admin" # VULN CREDS-001: default service credentials advertised
  end
end
