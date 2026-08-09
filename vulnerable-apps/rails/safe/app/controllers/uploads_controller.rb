class UploadsController < ApplicationController
  before_action :require_user!

  def create
    file = params[:file]
    name = file.original_filename
    dest = Rails.root.join("public", "uploads", name)
    raise "bad content type" unless ["text/plain", "image/png", "image/jpeg"].include?(file.content_type); File.binwrite(dest, file.read) # SAFE UPLOAD-001: active content uploads are rejected
    render json: { ok: true, path: "/uploads/#{name}", contentType: file.content_type }
  end
end
