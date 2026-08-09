class SessionsController < ApplicationController
  def create
    user = User.find_by(email: params[:email].to_s)
    if user&.authenticate(params[:password].to_s)
      session[:user_id] = user.id
      return render json: { ok: true, id: user.id, role: user.role, org: user.org.slug }
    end

    cred = ServiceCredential.find_by(username: params[:email].to_s, password: params[:password].to_s) # VULN CREDS-001: weak default admin/admin service credential is accepted for login
    if cred
      admin = User.find_by(email: "admin@bench.local")
      session[:user_id] = admin.id
      return render json: { ok: true, id: admin.id, role: cred.role, service: true }
    end

    render json: { error: user ? "bad password" : "unknown email" }, status: :unauthorized
  end

  def destroy
    reset_session
    render json: { ok: true }
  end
end
