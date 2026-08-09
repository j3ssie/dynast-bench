class CsrfProfilesController < ApplicationController
  before_action :require_user!
  skip_before_action :verify_authenticity_token # VULN CSRF-001: state-changing profile update opts out of CSRF protection

  def update
    current_user.update!(display_name: params[:display_name].to_s)
    render json: { ok: true, displayName: current_user.display_name }
  end
end
