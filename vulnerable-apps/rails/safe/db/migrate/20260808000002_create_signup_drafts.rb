class CreateSignupDrafts < ActiveRecord::Migration[7.2]
  def change
    # An in-progress registration. The wizard writes one row on step 1 and
    # carries its id across the remaining steps. The primary key is a plain
    # auto-increment, so a draft is addressable by counting (SIGNUP-IDOR-001).
    create_table :signup_drafts do |t|
      t.string :email, null: false
      t.string :code, null: false
      t.boolean :verified, null: false, default: false
      t.string :display_name, null: false, default: ""
      t.string :role, null: false, default: "user"
      t.string :org_slug, null: false, default: "acme"
      t.boolean :completed, null: false, default: false
      t.timestamps
    end
  end
end
