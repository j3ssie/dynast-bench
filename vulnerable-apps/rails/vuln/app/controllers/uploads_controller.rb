class UploadsController < ApplicationController
  before_action :require_user!

  def create
    file = params[:file]
    name = file.original_filename
    dest = Rails.root.join("public", "uploads", name)
    File.binwrite(dest, file.read) # VULN UPLOAD-001: unrestricted SVG/HTML upload is served from web root
    render json: { ok: true, path: "/uploads/#{name}", contentType: file.content_type }
  end
end
