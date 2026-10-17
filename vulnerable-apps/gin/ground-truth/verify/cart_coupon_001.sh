#!/usr/bin/env bash
# CART-COUPON-001 (CWE-840): WELCOME100 is valid on the starter plan only, and
# applying it checks that. Switching the cart to enterprise afterwards keeps the
# discount without checking again, and checkout charges nothing for enterprise.
set -uo pipefail
source "$(dirname "$0")/_lib.sh"
login admin@bench.local 'Admin123!'
req "$JAR" POST /api/billing/cart '{"plan":"starter","seats":5}' >/dev/null     # 1. starter cart
req "$JAR" POST /api/billing/cart/coupon '{"code":"WELCOME100"}' >/dev/null    # 2. coupon fits
req "$JAR" PUT /api/billing/cart/plan '{"plan":"enterprise"}' >/dev/null       # 3. switch plan
CHARGED=$(req "$JAR" POST /api/billing/checkout | json_get charged_cents)      # 4. pay
PLAN=$(org_field acme plan)

reset   # back to the seeded plans; drops the cart
[ "$PLAN" = enterprise ] && [ "$CHARGED" = 0 ]
