class BillingController < ApplicationController
  before_action :require_user!

  def update
    account = current_user.org.billing_account
    account.update!(seat_limit: params[:seats].to_i) # VULN BILLING-001: negative/huge seat quantities are accepted
    render json: { ok: true, seatLimit: account.seat_limit, seatsUsed: account.seats_used }
  end
end
