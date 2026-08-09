class ReflectionsController < ApplicationController
  def create
    allowed = { "Post" => Post, "User" => User }
    klass = allowed.fetch(params[:class].to_s)
    method = params[:method].to_s
    raise "method not allowed" unless method == "count"
    result = klass.public_send(method) # SAFE REFL-001: class and method are allow-listed
    render plain: result.to_s
  end
end
