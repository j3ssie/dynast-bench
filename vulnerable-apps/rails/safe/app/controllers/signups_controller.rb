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

  # FIXED SIGNUP-TOKEN-001: the verification code is a CSPRNG draw, unrelated to
  # when the signup started, so it can only be received in the email.
  def new_code
    format("%06d", SecureRandom.random_number(1_000_000))
  end

  # NEAR-MISS NM-SIGNUP-TOKEN-001: the same "mint a secret the user presents back"
  # job, done correctly with the CSPRNG. Not a bug.
  def new_invite_token
    SecureRandom.hex(32)
  end

  # FIXED SIGNUP-ENUM-001: step 1 answers the same way whether or not the address
  # is already registered - always 200 with a draft id. When the address is taken
  # the "already registered" signal goes only to the inbox, never to the response.
  def start
    email = params[:email].to_s
    return render(json: { error: "email required" }, status: :bad_request) if email.empty?

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

  # FIXED SIGNUP-MASSASSIGN-001: only the one field this step owns is written.
  # role and org_slug are never client-writable, so a crafted body cannot
  # self-promote or switch tenant.
  def profile
    draft = SignupDraft.find_by(id: params[:draftId])
    return render(json: { error: "unknown draft" }, status: :not_found) unless draft

    draft.update!(display_name: params[:display_name].to_s)
    render json: { ok: true, step: "complete", displayName: draft.display_name }
  end

  # FIXED SIGNUP-STEPSKIP-001: the final step enforces the state the flow depends
  # on - a draft that never reached the verified step cannot be completed, so
  # jumping straight here for an unverified mailbox is rejected.
  def complete
    draft = SignupDraft.find_by(id: params[:draftId])
    return render(json: { error: "unknown draft" }, status: :not_found) unless draft
    return render(json: { error: "email not verified" }, status: :forbidden) unless draft.verified
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

  # FIXED SIGNUP-IDOR-001: reading a draft requires presenting the code emailed to
  # that address (proof of ownership), and the code is never echoed back. A
  # stranger counting ids has neither the code to pass the check nor a way to
  # harvest one, so every in-progress signup stays private.
  def draft
    draft = SignupDraft.find_by(id: params[:id])
    return render(json: { error: "unknown draft" }, status: :not_found) unless draft
    unless ActiveSupport::SecurityUtils.secure_compare(draft.code, request.headers["X-Draft-Code"].to_s)
      return render(json: { error: "forbidden" }, status: :forbidden)
    end

    render json: draft.as_json(except: [:code])
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
