class PagesController < ApplicationController
  def show
    @post = Post.includes(:comments).find(params[:id])
    render template: "posts/show"
  end

  def search
    @q = params[:q].to_s
    render template: "posts/search"
  end
end
