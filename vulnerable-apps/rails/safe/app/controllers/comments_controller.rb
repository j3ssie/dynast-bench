class CommentsController < ApplicationController
  before_action :require_user!

  def create
    post = Post.find(params[:id])
    comment = post.comments.create!(user: current_user, body: params[:body].to_s)
    render json: { ok: true, id: comment.id, body: comment.body }
  end
end
