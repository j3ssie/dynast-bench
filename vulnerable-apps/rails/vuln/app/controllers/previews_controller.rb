class PreviewsController < ApplicationController
  def inline
    render inline: params[:tpl].to_s # VULN SSTI-001: user-controlled ERB is evaluated server-side
  end

  def safe_preview
    @name = params[:name].to_s
    render plain: "Preview for #{@name}"
  end
end
