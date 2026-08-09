class ExportsController < ApplicationController
  def show
    name = params[:name].to_s
    return render plain: "bad name", status: :bad_request unless name.match?(/\A[\w.-]+\z/); output = IO.popen(["printf", "export-%s", name], &:read) # SAFE CMD-001: reject shell metacharacters and use argv array
    render plain: output
  end
end
