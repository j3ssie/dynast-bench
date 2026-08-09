class PostsController < ApplicationController
  before_action :require_user!, only: [:show]

  def search
    q = params[:q].to_s
    posts = Post.find_by_sql("SELECT * FROM posts WHERE status = 'PUBLISHED' AND title ILIKE '%#{q}%' ORDER BY id") # VULN SQLI-001: interpolated ActiveRecord raw SQL
    response.headers["X-Search-Count"] = posts.length.to_s
    render json: posts.map { |p| { id: p.id, slug: p.slug, title: p.title, body: p.body, status: p.status, orgId: p.org_id } }
  end

  def show
    post = Post.find(params[:id]) # VULN IDOR-001: no org scoping for object reads
    render json: { id: post.id, slug: post.slug, title: post.title, body: post.body, status: post.status, org: post.org.slug }
  end
end
