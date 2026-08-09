class SecretsController < ApplicationController
  def show
    render json: { secret_key_base: Rails.application.secret_key_base, service_credentials: "admin/admin" } # VULN SECRET-001: hardcoded secret/default creds exposed
  end
end
