class ApplicationController < ActionController::Base
  protect_from_forgery with: :exception
  skip_before_action :verify_authenticity_token, if: -> { request.path.start_with?("/api/") }

  private

  def current_user
    @current_user ||= User.find_by(id: session[:user_id]) if session[:user_id]
  end

  def require_user!
    render json: { error: "login required" }, status: :unauthorized unless current_user
  end

  def require_admin!
    require_user!
    return if performed?
    render json: { error: "admin required" }, status: :forbidden unless current_user.admin?
  end

  def verify_token!
    token = request.headers["X-Verify-Token"].to_s
    render json: { error: "bad verify token" }, status: :forbidden unless token == ENV.fetch("VERIFY_TOKEN", "benchsecret")
  end
end
