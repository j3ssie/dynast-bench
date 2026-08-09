class BillingController < ApplicationController
  before_action :require_user!

  def update
    account = current_user.org.billing_account
    seats = Integer(params[:seats]); raise ArgumentError unless seats.between?(account.seats_used, 100); account.update!(seat_limit: seats) # SAFE BILLING-001: seat quantities are bounded and cannot undercut usage
    render json: { ok: true, seatLimit: account.seat_limit, seatsUsed: account.seats_used }
  end
end
