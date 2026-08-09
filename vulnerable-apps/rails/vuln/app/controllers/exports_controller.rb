class ExportsController < ApplicationController
  def show
    name = params[:name].to_s
    output = `printf export-#{name}` # VULN CMD-001: shell command interpolation allows command injection
    render plain: output
  end
end
