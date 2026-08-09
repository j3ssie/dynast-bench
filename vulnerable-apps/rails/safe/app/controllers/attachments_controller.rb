class AttachmentsController < ApplicationController
  def download
    base = Rails.root.join("public", "attachments").realpath
    path = base.join(params[:name].to_s).realpath # SAFE TRAVERSAL-001: resolved path must stay inside attachment directory
    raise ActionController::RoutingError, "not found" unless path.to_s.start_with?(base.to_s + File::SEPARATOR)
    send_file path, disposition: "inline"
  end
end
