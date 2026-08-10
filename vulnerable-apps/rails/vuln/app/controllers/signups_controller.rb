# The four-step registration wizard (start -> verify -> profile -> complete). The
# server keeps flow state in a signup_drafts row, so each step is its own request
# carrying only the draft id. Driven by fetch from the wizard, and every /api/*
# route is CSRF-exempt (see ApplicationController), so these appear in no HTML.
class SignupsController < ApplicationController
  # The wizard page itself (pre-auth HTML). All the state-changing work is in the
  # /api/signup/* actions below, which the page drives with fetch.
  def wizard
    render template: "signups/wizard", layout: false
  end

  # SIGNUP-TOKEN-001 (CWE-330/CWE-640): the emailed verification code is the last
  # six digits of the wall clock, not a CSPRNG draw, so anyone who can start a
  # signup for an address (or knows roughly when one started) can recompute the
  # code instead of receiving it. The safe twin uses SecureRandom.
  def new_code
    Time.now.to_i.to_s.last(6)
  end

  # NEAR-MISS NM-SIGNUP-TOKEN-001: the same "mint a secret the user presents back"
  # job, done correctly with the CSPRNG. Not a bug.
  def new_invite_token
    SecureRandom.hex(32)
  end

  # SIGNUP-ENUM-001 (CWE-204): step 1 answers 409 for a registered address and
  # 200 for an unknown one, so pre-auth, unthrottled registration is a free oracle
  # for testing an address list. The safe twin always returns 200.
  def start
    email = params[:email].to_s
    return render(json: { error: "email required" }, status: :bad_request) if email.empty?

    if User.exists?(email: email)
      return render json: { error: "that email is already registered", registered: true }, status: :conflict
    end
    draft = SignupDraft.create!(email: email, code: new_code)
    render json: { draftId: draft.id, step: "verify" }
  end

  def verify
    draft = SignupDraft.find_by(id: params[:draftId])
    return render(json: { error: "unknown draft" }, status: :not_found) unless draft
    return render(json: { error: "incorrect code" }, status: :bad_request) if draft.code != params[:code].to_s

    draft.update!(verified: true)
    render json: { ok: true, step: "profile" }
  end

  # SIGNUP-MASSASSIGN-001 (CWE-915): the strong-params permit list on the profile
  # step includes role and org_slug - the two fields the final step hands to the
  # new User. The wizard only sends display_name, but a crafted body sets role or
  # org_slug too, so registration can self-assign admin or join another tenant.
  def profile
    draft = SignupDraft.find_by(id: params[:draftId])
    return render(json: { error: "unknown draft" }, status: :not_found) unless draft

    draft.update!(params.permit(:display_name, :role, :org_slug))
    render json: { ok: true, step: "complete", displayName: draft.display_name }
  end

  # SIGNUP-STEPSKIP-001 (CWE-841): the final step never checks that the draft
  # reached the verified state. In the wizard a draft always is verified by the
  # time it gets here, but the steps are independent requests - posting straight to
  # this one with a fresh draft id registers an unverified, unowned mailbox.
  def complete
    draft = SignupDraft.find_by(id: params[:draftId])
    return render(json: { error: "unknown draft" }, status: :not_found) unless draft
    return render(json: { error: "already completed" }, status: :conflict) if draft.completed

    org = Org.find_by(slug: draft.org_slug)
    return render(json: { error: "unknown org" }, status: :bad_request) unless org

    user = User.create!(
      org: org,
      email: draft.email,
      password: params[:password].presence || "Changeme123!",
      role: draft.role,
      is_admin: draft.role == "admin",
      display_name: draft.display_name.presence || "New User",
    )
    draft.update!(completed: true)
    render json: { ok: true, id: user.id, email: user.email, role: user.role }
  end

  # SIGNUP-IDOR-001 (CWE-639): the wizard reloads its own draft by id after a
  # refresh, and the handler returns whatever row that id names - no ownership
  # check, no session, over an auto-increment id, and the row carries the email AND
  # the verification code emailed to it. Count down to walk every registration.
  def draft
    draft = SignupDraft.find_by(id: params[:id])
    return render(json: { error: "unknown draft" }, status: :not_found) unless draft

    render json: draft
  end

  # NEAR-MISS NM-SIGNUP-RESEND-001: the sibling of start() - same pre-auth surface,
  # same "does this address exist" shape - but the response is constant whatever
  # the answer and it is rate limited per address, so it is neither an enumeration
  # oracle nor a mail cannon. Not a bug.
  def resend
    email = params[:email].to_s.downcase
    constant = { ok: true, message: "if that signup exists, a code is on its way" }
    return render(json: constant) if email.empty?

    key = "signup:resend:#{email}"
    count = Rails.cache.read(key).to_i
    return render(json: constant) if count >= 3

    Rails.cache.write(key, count + 1, expires_in: 300)
    render json: constant
  end
end
