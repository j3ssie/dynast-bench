Rails.application.routes.draw do
  root "home#index"
  post "/api/auth/login", to: "sessions#create"
  delete "/api/auth/logout", to: "sessions#destroy"

  # Multi-step signup wizard (client-driven; the /api/signup/* endpoints appear in
  # no served HTML) and the click-gated Advanced report builder.
  get "/signup", to: "signups#wizard"
  post "/api/signup/start", to: "signups#start"
  post "/api/signup/verify", to: "signups#verify"
  post "/api/signup/profile", to: "signups#profile"
  post "/api/signup/complete", to: "signups#complete"
  post "/api/signup/resend", to: "signups#resend"
  get "/api/signup/draft/:id", to: "signups#draft"
  post "/api/tools/report", to: "advanced#report"

  get "/api/_verify/health", to: "verify#health"
  get "/api/_verify/user", to: "verify#user"
  get "/api/_verify/post", to: "verify#post"

  get "/api/users/me", to: "users#me"
  patch "/api/users/me", to: "users#update"
  patch "/api/profile", to: "profiles#update"
  post "/api/users/:id/promote", to: "users#promote"

  post "/api/import/yaml", to: "imports#yaml_load"
  post "/api/import/json", to: "imports#json_import"
  post "/api/preview/inline", to: "previews#inline"
  post "/api/preview/safe", to: "previews#safe_preview"
  post "/api/admin/check_email", to: "admin_checks#check_email"

  get "/api/posts/search", to: "posts#search"
  get "/api/posts/:id", to: "posts#show"
  post "/api/posts/:id/comments", to: "comments#create"
  get "/posts/search", to: "pages#search"
  get "/posts/:id", to: "pages#show"

  post "/api/reports", to: "reports#create"
  get "/api/reports/:id/run", to: "reports#run"
  get "/api/fetch", to: "fetches#show"
  get "/api/export", to: "exports#show"
  post "/api/reflect", to: "reflections#create"
  get "/api/secrets", to: "secrets#show"
  get "/goto", to: "redirects#show"
  get "/api/attachments/download", to: "attachments#download"
  post "/api/csrf/profile", to: "csrf_profiles#update"
  post "/api/billing/seats", to: "billing#update"
  post "/api/invites", to: "invites#create"
  post "/api/uploads", to: "uploads#create"
end
