class AttachmentsController < ApplicationController
  def download
    path = Rails.root.join("public", "attachments", params[:name].to_s) # VULN TRAVERSAL-001: untrusted filename can escape attachment directory
    send_file path, disposition: "inline"
  end
end
