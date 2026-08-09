class ReflectionsController < ApplicationController
  def create
    klass = params[:class].to_s.constantize
    method = params[:method].to_s
    args = Array(params[:args])
    result = klass.send(method, *args) # VULN REFL-001: constantize + send on user input invokes arbitrary methods
    render plain: result.to_s
  end
end
