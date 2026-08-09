Comment.delete_all
Invite.delete_all
Report.delete_all
Post.delete_all
User.delete_all
BillingAccount.delete_all
Org.delete_all
ServiceCredential.delete_all

acme = Org.create!(name: "Acme", slug: "acme")
globex = Org.create!(name: "Globex", slug: "globex")

admin = User.create!(org: acme, email: "admin@bench.local", password: "Admin123!", role: "admin", is_admin: true, display_name: "Acme Admin")
editor = User.create!(org: acme, email: "editor@bench.local", password: "Editor123!", role: "editor", display_name: "Acme Editor")
user1 = User.create!(org: acme, email: "user1@bench.local", password: "User123!", role: "user", display_name: "Acme User")
user2 = User.create!(org: globex, email: "user2@bench.local", password: "User123!", role: "user", display_name: "Globex User")

Post.create!(org: acme, author: editor, slug: "acme-welcome", title: "Acme Welcome", status: "PUBLISHED", body: "Welcome to Acme public notes")
Post.create!(org: acme, author: admin, slug: "acme-roadmap", title: "Acme Roadmap", status: "PUBLISHED", body: "Roadmap visible to Acme users")
Post.create!(org: globex, author: user2, slug: "globex-internal", title: "Globex Internal", status: "DRAFT", body: "GLOBEX-CONFIDENTIAL-MARKER-7f3a draft body")
Post.create!(org: globex, author: user2, slug: "globex-public", title: "Globex Public", status: "PUBLISHED", body: "Globex public update")

BillingAccount.create!(org: acme, seat_limit: 2, seats_used: 1)
BillingAccount.create!(org: globex, seat_limit: 2, seats_used: 1)
ServiceCredential.create!(username: "admin", password: "admin", role: "admin")

attachments = Rails.root.join("public", "attachments")
FileUtils.mkdir_p(attachments)
File.write(attachments.join("welcome.txt"), "public attachment\n")
