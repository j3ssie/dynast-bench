class ProfilesController < ApplicationController
  before_action :require_user!

  def update
    attrs = params.require(:profile).permit(:display_name, :bio)
    current_user.update!(attrs)
    render json: { ok: true, displayName: current_user.display_name, bio: current_user.bio }
  end
end
