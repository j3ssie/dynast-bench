class InvitesController < ApplicationController
  before_action :require_user!

  def create
    account = current_user.org.billing_account
    account.with_lock do # SAFE RACE-001: seat check and update are serialized
      if account.seats_used < account.seat_limit
        Invite.create!(org: current_user.org, inviter: current_user, email: params[:email].to_s)
        account.update!(seats_used: account.seats_used + 1)
        render json: { ok: true, seatsUsed: account.reload.seats_used, seatLimit: account.seat_limit }
      else
        render json: { error: "seat limit reached", seatsUsed: account.seats_used, seatLimit: account.seat_limit }, status: :conflict
      end
    end
  end
end
