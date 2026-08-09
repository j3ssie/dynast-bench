class UsersController < ApplicationController
  before_action :require_user!, except: []

  def me
    render json: { id: current_user.id, email: current_user.email, role: current_user.role, isAdmin: current_user.is_admin, org: current_user.org.slug, displayName: current_user.display_name }
  end

  def update
    attrs = params.require(:user).permit(:display_name, :bio) # SAFE MASSASSIGN-001: explicit strong params exclude role/is_admin/org_id
    current_user.update!(attrs)
    render json: { ok: true, role: current_user.role, isAdmin: current_user.is_admin, orgId: current_user.org_id }
  end

  def promote
    require_admin! # SAFE AUTHZ-001: privileged promotion requires admin authorization
    return if performed?
    target = User.find(params[:id])
    target.update!(role: "admin", is_admin: true)
    render json: { ok: true, promoted: target.email, role: target.role }
  end
end
