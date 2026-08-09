class CreateDomain < ActiveRecord::Migration[7.2]
  def change
    create_table :orgs do |t|
      t.string :name, null: false
      t.string :slug, null: false
      t.timestamps
    end
    add_index :orgs, :slug, unique: true

    create_table :users do |t|
      t.references :org, null: false, foreign_key: true
      t.string :email, null: false
      t.string :password_digest, null: false
      t.string :role, null: false, default: "user"
      t.boolean :is_admin, null: false, default: false
      t.string :display_name
      t.text :bio
      t.timestamps
    end
    add_index :users, :email, unique: true

    create_table :posts do |t|
      t.references :org, null: false, foreign_key: true
      t.references :author, null: false, foreign_key: { to_table: :users }
      t.string :slug, null: false
      t.string :title, null: false
      t.string :status, null: false, default: "DRAFT"
      t.text :body
      t.timestamps
    end
    add_index :posts, :slug, unique: true

    create_table :comments do |t|
      t.references :post, null: false, foreign_key: true
      t.references :user, null: false, foreign_key: true
      t.text :body, null: false
      t.timestamps
    end

    create_table :reports do |t|
      t.references :user, null: false, foreign_key: true
      t.string :name, null: false
      t.timestamps
    end

    create_table :billing_accounts do |t|
      t.references :org, null: false, foreign_key: true
      t.integer :seat_limit, null: false, default: 2
      t.integer :seats_used, null: false, default: 1
      t.timestamps
    end

    create_table :invites do |t|
      t.references :org, null: false, foreign_key: true
      t.references :inviter, null: false, foreign_key: { to_table: :users }
      t.string :email, null: false
      t.timestamps
    end

    create_table :service_credentials do |t|
      t.string :username, null: false
      t.string :password, null: false
      t.string :role, null: false, default: "service"
      t.timestamps
    end
  end
end
