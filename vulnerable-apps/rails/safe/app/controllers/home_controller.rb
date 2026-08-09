class HomeController < ApplicationController
  def index
    @public_message = "TaskFlow Rails demo"
    @leaked_secret = "configured-at-runtime" # SAFE SECRET-001: do not render the signing secret
    @default_creds = "disabled" # SAFE CREDS-001: do not advertise default credentials
  end
end
