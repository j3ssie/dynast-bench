<?php

namespace Database\Seeders;

use App\Models\Comment;
use App\Models\Invitation;
use App\Models\Organization;
use App\Models\Post;
use App\Models\Subscription;
use App\Models\User;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\Hash;

class DatabaseSeeder extends Seeder
{
    public function run(): void
    {
        $acme = Organization::create(['name' => 'Acme', 'slug' => 'acme']);
        $globex = Organization::create(['name' => 'Globex', 'slug' => 'globex']);

        // Set columns explicitly (not via mass assignment) so seeding is
        // identical in both variants regardless of the User $fillable allowlist.
        $mk = function (array $a): User {
            $u = new User();
            $u->organization_id = $a['org'];
            $u->name = $a['name'];
            $u->email = $a['email'];
            $u->password = Hash::make($a['password']);
            $u->role = $a['role'];
            $u->is_admin = $a['admin'] ?? false;
            $u->verified = true;
            $u->email_verified_at = now();
            $u->save();

            return $u;
        };

        $admin = $mk(['org' => $acme->id, 'name' => 'Acme Admin', 'email' => 'admin@bench.local', 'password' => 'Admin123!', 'role' => 'admin', 'admin' => true]);
        $editor = $mk(['org' => $acme->id, 'name' => 'Acme Editor', 'email' => 'editor@bench.local', 'password' => 'Editor123!', 'role' => 'editor']);
        $user1 = $mk(['org' => $acme->id, 'name' => 'Acme User', 'email' => 'user1@bench.local', 'password' => 'User123!', 'role' => 'user']);
        $user2 = $mk(['org' => $globex->id, 'name' => 'Globex User', 'email' => 'user2@bench.local', 'password' => 'User123!', 'role' => 'user']);
        // DEFAULT-CREDS-001 (CWE-1392): weak service account admin/admin (vuln/ only).
        $mk(['org' => $acme->id, 'name' => 'Weak Service Admin', 'email' => 'admin', 'password' => 'admin', 'role' => 'service', 'admin' => true]);

        Post::create(['organization_id' => $acme->id, 'user_id' => $editor->id, 'slug' => 'acme-welcome', 'title' => 'Acme Welcome', 'body' => 'Public Acme launch notes.', 'status' => 'published']);
        Post::create(['organization_id' => $acme->id, 'user_id' => $user1->id, 'slug' => 'acme-roadmap', 'title' => 'Acme Roadmap', 'body' => 'Acme internal roadmap draft.', 'status' => 'draft']);
        Post::create(['organization_id' => $globex->id, 'user_id' => $user2->id, 'slug' => 'globex-public', 'title' => 'Globex Public', 'body' => 'Globex public update.', 'status' => 'published']);
        // The confidential Globex DRAFT — only reachable via SQLi/IDOR.
        $secret = Post::create(['organization_id' => $globex->id, 'user_id' => $user2->id, 'slug' => 'globex-internal', 'title' => 'Globex Draft', 'body' => 'GLOBEX-CONFIDENTIAL-MARKER-7f3a', 'status' => 'draft']);

        Comment::create(['post_id' => $secret->id, 'user_id' => $user2->id, 'body' => 'Internal only.']);

        Subscription::create(['organization_id' => $acme->id, 'seats_total' => 5, 'seats_used' => 3, 'balance_cents' => 0]);
        Subscription::create(['organization_id' => $globex->id, 'seats_total' => 5, 'seats_used' => 2, 'balance_cents' => 0]);

        Invitation::create(['organization_id' => $acme->id, 'email' => 'invitee@bench.local', 'token' => 'seed-invite-token']);
    }
}
