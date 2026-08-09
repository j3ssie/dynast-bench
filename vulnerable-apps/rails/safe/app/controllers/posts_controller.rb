class PostsController < ApplicationController
  before_action :require_user!, only: [:show]

  def search
    q = params[:q].to_s
    posts = Post.where(status: "PUBLISHED").where("title ILIKE ?", "%#{q}%").order(:id) # SAFE SQLI-001: q is bound as a parameter
    response.headers["X-Search-Count"] = posts.length.to_s
    render json: posts.map { |p| { id: p.id, slug: p.slug, title: p.title, body: p.body, status: p.status, orgId: p.org_id } }
  end

  def show
    post = current_user.org.posts.find(params[:id]) # SAFE IDOR-001: object reads are scoped to the current tenant
    render json: { id: post.id, slug: post.slug, title: post.title, body: post.body, status: post.status, org: post.org.slug }
  end
end
