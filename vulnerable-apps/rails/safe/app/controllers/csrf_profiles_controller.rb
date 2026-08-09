class CsrfProfilesController < ApplicationController
  before_action :require_user!
  # SAFE CSRF-001: keep Rails CSRF verification enabled for cookie-authenticated profile changes

  def update
    current_user.update!(display_name: params[:display_name].to_s)
    render json: { ok: true, displayName: current_user.display_name }
  end
end
