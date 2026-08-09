class InvitesController < ApplicationController
  before_action :require_user!

  def create
    account = current_user.org.billing_account
    if account.seats_used < account.seat_limit # VULN RACE-001: check/create/update are not locked, so concurrent invites exceed seats
      sleep 0.2
      Invite.create!(org: current_user.org, inviter: current_user, email: params[:email].to_s)
      account.update!(seats_used: account.seats_used + 1)
      render json: { ok: true, seatsUsed: account.reload.seats_used, seatLimit: account.seat_limit }
    else
      render json: { error: "seat limit reached", seatsUsed: account.seats_used, seatLimit: account.seat_limit }, status: :conflict
    end
  end
end
