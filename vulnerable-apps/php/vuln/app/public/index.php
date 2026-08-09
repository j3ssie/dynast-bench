<?php require_once __DIR__ . '/../inc/auth.php'; $u = current_user(); ?>
<!doctype html><title>Classic PHP Bench</title>
<h1>Classic PHP Bench</h1>
<p>Intentionally vulnerable local benchmark app.</p>
<p><?= $u ? 'Logged in as ' . htmlspecialchars($u['email'], ENT_QUOTES) : 'Not logged in' ?></p>
<ul>
  <li><a href="/login.php">login</a></li>
  <li><a href="/search.php?q=Acme">search</a></li>
  <li><a href="/page.php?page=pages/home.php">page include</a></li>
</ul>
