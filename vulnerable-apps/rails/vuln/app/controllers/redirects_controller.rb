class RedirectsController < ApplicationController
  def show
    redirect_to params[:next].to_s, allow_other_host: true # VULN REDIRECT-001: arbitrary open redirect
  end
end
