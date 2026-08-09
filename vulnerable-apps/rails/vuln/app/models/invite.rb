class Invite < ApplicationRecord
  belongs_to :org
  belongs_to :inviter, class_name: "User"
end
