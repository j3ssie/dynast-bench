class RedirectsController < ApplicationController
  def show
    redirect_to "/", allow_other_host: false # SAFE REDIRECT-001: redirect target is constrained to this app
  end
end
