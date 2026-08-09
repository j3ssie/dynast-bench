class SecretsController < ApplicationController
  def show
    render json: { secret_key_base: "configured-at-runtime", service_credentials: "disabled" } # SAFE SECRET-001: secrets and default credentials are not exposed
  end
end
