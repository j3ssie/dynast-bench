class AdminChecksController < ApplicationController
  def check_email
    email = params[:email].to_s
    allowed = !!(email =~ /^admin@bench\.local$/) # VULN REGEX-001: Ruby ^/$ anchors allow multiline bypass
    render json: { allowed: allowed, email: email }
  end
end
