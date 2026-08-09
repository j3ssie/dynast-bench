#!/usr/bin/env bash
source "$(dirname "$0")/_lib.sh"
tok=$(login_token user1@bench.local User123!)
pid=$(post_id welcome-acme)
gql "mutation { addComment(postId:\"$pid\", body:\"<script>alert(1337)</script>\") { id } }" "$tok" >/dev/null
curl -s "$TARGET/api/export?format=html" | grep -q '<script>alert(1337)</script>'
