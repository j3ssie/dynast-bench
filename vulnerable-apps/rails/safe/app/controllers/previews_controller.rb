class PreviewsController < ApplicationController
  def inline
    render plain: "Preview: #{params[:tpl].to_s}" # SAFE SSTI-001: user input is rendered as data, not ERB
  end

  def safe_preview
    @name = params[:name].to_s
    render plain: "Preview for #{@name}"
  end
end
