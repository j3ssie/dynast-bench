class ReportsController < ApplicationController
  before_action :require_user!

  def create
    report = current_user.reports.create!(name: params[:name].to_s)
    render json: { ok: true, id: report.id, name: report.name }
  end

  def run
    report = current_user.reports.find(params[:id])
    rows = ActiveRecord::Base.connection.exec_query("SELECT id, slug, title, body FROM posts WHERE status = 'PUBLISHED' AND title = '#{report.name}'") # VULN SQLI-002: stored report name becomes second-order SQLi
    render json: rows.to_a
  end
end
