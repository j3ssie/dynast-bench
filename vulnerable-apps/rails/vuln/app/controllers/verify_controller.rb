class VerifyController < ApplicationController
  skip_before_action :verify_authenticity_token
  before_action :verify_token!, except: [:health]

  def health
    ActiveRecord::Base.connection.execute("SELECT 1")
    render json: { status: "ok", db: "ok", app: "rails" }
  rescue => e
    render json: { status: "error", db: e.class.name }, status: :service_unavailable
  end

  def user
    user = User.includes(:org).find_by(email: params[:email].to_s)
    render json: user ? { exists: true, id: user.id, role: user.role, isAdmin: user.is_admin, verified: true, orgSlug: user.org.slug, displayName: user.display_name } : { exists: false }
  end

  def post
    post = Post.includes(:org, :author).find_by(slug: params[:slug].to_s)
    render json: post ? { exists: true, id: post.id, slug: post.slug, status: post.status, authorEmail: post.author.email, orgSlug: post.org.slug, title: post.title } : { exists: false }
  end
end
