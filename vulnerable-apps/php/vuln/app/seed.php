<?php
require_once __DIR__ . '/inc/db.php';
$pdo = pdo();
foreach (['signup_drafts', 'comments', 'posts', 'users', 'orgs'] as $table) { $pdo->exec("DROP TABLE IF EXISTS $table"); }
$pdo->exec("CREATE TABLE orgs (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(100), slug VARCHAR(50) UNIQUE) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
$pdo->exec("CREATE TABLE users (id INT AUTO_INCREMENT PRIMARY KEY, org_id INT NOT NULL, email VARCHAR(190) UNIQUE, password_hash VARCHAR(255), role VARCHAR(50), is_admin TINYINT(1) DEFAULT 0, verified TINYINT(1) DEFAULT 1, display_name VARCHAR(100), reset_token VARCHAR(100), FOREIGN KEY (org_id) REFERENCES orgs(id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
$pdo->exec("CREATE TABLE posts (id INT AUTO_INCREMENT PRIMARY KEY, org_id INT NOT NULL, author_id INT NOT NULL, slug VARCHAR(120) UNIQUE, title VARCHAR(255), body TEXT, status VARCHAR(40), FOREIGN KEY (org_id) REFERENCES orgs(id), FOREIGN KEY (author_id) REFERENCES users(id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
$pdo->exec("CREATE TABLE comments (id INT AUTO_INCREMENT PRIMARY KEY, post_id INT NOT NULL, user_id INT NOT NULL, body TEXT, FOREIGN KEY (post_id) REFERENCES posts(id), FOREIGN KEY (user_id) REFERENCES users(id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
$pdo->exec("CREATE TABLE signup_drafts (id INT AUTO_INCREMENT PRIMARY KEY, email VARCHAR(190) NOT NULL, code VARCHAR(16) NOT NULL, verified TINYINT(1) DEFAULT 0, display_name VARCHAR(100) DEFAULT '', role VARCHAR(50) DEFAULT 'user', org_slug VARCHAR(50) DEFAULT 'acme', completed TINYINT(1) DEFAULT 0) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
$pdo->prepare('INSERT INTO orgs (name, slug) VALUES (?, ?), (?, ?)')->execute(['Acme', 'acme', 'Globex', 'globex']);
$orgs = [];
foreach ($pdo->query('SELECT id, slug FROM orgs') as $row) { $orgs[$row['slug']] = (int)$row['id']; }
$addUser = $pdo->prepare('INSERT INTO users (org_id,email,password_hash,role,is_admin,verified,display_name) VALUES (?,?,?,?,?,?,?)');
$users = [
    [$orgs['acme'], 'admin@bench.local', 'Admin123!', 'admin', 1, 1, 'Acme Admin'],
    [$orgs['acme'], 'editor@bench.local', 'Editor123!', 'editor', 0, 1, 'Acme Editor'],
    [$orgs['acme'], 'user1@bench.local', 'User123!', 'user', 0, 1, 'Acme User'],
    [$orgs['globex'], 'user2@bench.local', 'User123!', 'user', 0, 1, 'Globex User'],
    [$orgs['acme'], 'admin', 'admin', 'service', 1, 1, 'Weak Service Admin'],
];
foreach ($users as $u) { $addUser->execute([$u[0], $u[1], password_hash($u[2], PASSWORD_DEFAULT), $u[3], $u[4], $u[5], $u[6]]); }
$userIds = [];
foreach ($pdo->query('SELECT id, email FROM users') as $row) { $userIds[$row['email']] = (int)$row['id']; }
$addPost = $pdo->prepare('INSERT INTO posts (org_id,author_id,slug,title,body,status) VALUES (?,?,?,?,?,?)');
$addPost->execute([$orgs['acme'], $userIds['editor@bench.local'], 'acme-welcome', 'Acme Welcome', 'Public Acme launch notes.', 'published']);
$addPost->execute([$orgs['acme'], $userIds['user1@bench.local'], 'acme-roadmap', 'Acme Roadmap', 'Acme internal roadmap draft.', 'draft']);
$addPost->execute([$orgs['globex'], $userIds['user2@bench.local'], 'globex-public', 'Globex Public', 'Globex public update.', 'published']);
$addPost->execute([$orgs['globex'], $userIds['user2@bench.local'], 'globex-internal', 'Globex Draft', 'GLOBEX-CONFIDENTIAL-MARKER-7f3a', 'draft']);
@mkdir('/var/www/html/uploads', 0775, true);
@mkdir('/var/www/html/downloads', 0775, true);
file_put_contents('/var/www/html/downloads/report.txt', 'public report');
?>
