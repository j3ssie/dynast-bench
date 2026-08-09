class Org < ApplicationRecord
  has_many :users
  has_many :posts
  has_one :billing_account
end
