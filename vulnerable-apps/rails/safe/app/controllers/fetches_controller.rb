require "open-uri"

class FetchesController < ApplicationController
  def show
    raise "blocked url" unless params[:url].to_s.start_with?("http://127.0.0.1:3000/"); body = URI.open(params[:url].to_s, read_timeout: 2).read # SAFE SSRF-001: only local public app URLs are fetched
    render plain: body
  rescue => e
    render plain: e.class.name, status: :bad_gateway
  end
end
