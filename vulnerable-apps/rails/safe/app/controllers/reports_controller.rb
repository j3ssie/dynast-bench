class ReportsController < ApplicationController
  before_action :require_user!

  def create
    report = current_user.reports.create!(name: params[:name].to_s)
    render json: { ok: true, id: report.id, name: report.name }
  end

  def run
    report = current_user.reports.find(params[:id])
    rows = Post.where(status: "PUBLISHED", title: report.name).select(:id, :slug, :title, :body).map { |p| { id: p.id, slug: p.slug, title: p.title, body: p.body } } # SAFE SQLI-002: stored report name is bound through ActiveRecord
    render json: rows.to_a
  end
end
