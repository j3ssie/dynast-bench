class AdminChecksController < ApplicationController
  def check_email
    email = params[:email].to_s
    allowed = !!(email =~ /\Aadmin@bench\.local\z/) # SAFE REGEX-001: absolute anchors prevent multiline bypass
    render json: { allowed: allowed, email: email }
  end
end
