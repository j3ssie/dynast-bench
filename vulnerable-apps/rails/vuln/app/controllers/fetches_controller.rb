require "open-uri"

class FetchesController < ApplicationController
  def show
    body = URI.open(params[:url].to_s, read_timeout: 2).read # VULN SSRF-001: server fetches arbitrary user URL
    render plain: body
  rescue => e
    render plain: e.class.name, status: :bad_gateway
  end
end
