class User < ApplicationRecord
  belongs_to :org
  has_secure_password
  has_many :posts, foreign_key: :author_id
  has_many :reports
  def admin?
    is_admin || role == "admin"
  end
end
