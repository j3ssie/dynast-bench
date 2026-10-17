package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// ---------------------------------------------------------------------------
// Billing: a workspace admin builds a cart, applies a coupon, checks out.
//
//   GET  /api/billing/cart            the open cart
//   POST /api/billing/cart            start one: {plan, seats}
//   POST /api/billing/cart/coupon     apply a coupon: {code}
//   PUT  /api/billing/cart/seats      change the seat count
//   PUT  /api/billing/cart/plan       change the plan
//   POST /api/billing/checkout        pay what the cart says, switch plan
//   POST /api/billing/cancel          back to the free plan
// ---------------------------------------------------------------------------

// Per-seat monthly price, in cents.
var planPrices = map[string]int{"starter": 900, "team": 4900, "enterprise": 19900}

type coupon struct {
	PercentOff int
	Plans      []string
}

// WELCOME100 is the first-month promotion: free, but only on the starter plan.
var coupons = map[string]coupon{
	"WELCOME100": {PercentOff: 100, Plans: []string{"starter"}},
	"TEAM10":     {PercentOff: 10, Plans: []string{"team", "enterprise"}},
}

func (cp coupon) fits(plan string) bool {
	for _, p := range cp.Plans {
		if p == plan {
			return true
		}
	}
	return false
}

type Cart struct {
	OrgID  int
	Plan   string
	Seats  int
	Coupon string
	Price  int
}

// priceCart is the one place a cart's price is worked out: list price, then the
// coupon - which is dropped if it does not fit the cart as it now stands.
func priceCart(cart *Cart) {
	cart.Price = planPrices[cart.Plan] * cart.Seats
	if cart.Coupon == "" {
		return
	}
	cp, ok := coupons[cart.Coupon]
	if !ok || !cp.fits(cart.Plan) {
		cart.Coupon = ""
		return
	}
	cart.Price = cart.Price * (100 - cp.PercentOff) / 100
}

// billingAdmin is the caller when they are an admin of their workspace.
func billingAdmin(c *gin.Context) (User, bool) {
	user, ok := currentUser(c)
	if !ok {
		return User{}, false
	}
	if user.Role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "billing is for workspace admins"})
		return User{}, false
	}
	return user, true
}

func loadCart(c *gin.Context, orgID int) (Cart, bool) {
	cart := Cart{OrgID: orgID}
	err := db.QueryRowContext(c.Request.Context(), `SELECT plan,seats,coupon,price_cents FROM carts WHERE org_id=$1`, orgID).Scan(&cart.Plan, &cart.Seats, &cart.Coupon, &cart.Price)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "no open cart"})
		return cart, false
	}
	return cart, true
}

func saveCart(c *gin.Context, cart Cart) {
	_, _ = db.ExecContext(c.Request.Context(), `INSERT INTO carts(org_id,plan,seats,coupon,price_cents) VALUES($1,$2,$3,$4,$5)
		ON CONFLICT (org_id) DO UPDATE SET plan=EXCLUDED.plan, seats=EXCLUDED.seats, coupon=EXCLUDED.coupon, price_cents=EXCLUDED.price_cents`,
		cart.OrgID, cart.Plan, cart.Seats, cart.Coupon, cart.Price)
	c.JSON(http.StatusOK, cart.json())
}

func (cart Cart) json() gin.H {
	return gin.H{"plan": cart.Plan, "seats": cart.Seats, "coupon": cart.Coupon, "price_cents": cart.Price}
}

// adminCart is the caller's open cart, when the caller is a workspace admin.
func adminCart(c *gin.Context) (Cart, bool) {
	user, ok := billingAdmin(c)
	if !ok {
		return Cart{}, false
	}
	return loadCart(c, user.OrgID)
}

func validSeats(n int) bool { return n >= 1 && n <= 100 }

func getCart(c *gin.Context) {
	if cart, ok := adminCart(c); ok {
		c.JSON(http.StatusOK, cart.json())
	}
}

func startCart(c *gin.Context) {
	user, ok := billingAdmin(c)
	if !ok {
		return
	}
	var in struct {
		Plan  string `json:"plan"`
		Seats int    `json:"seats"`
	}
	_ = c.ShouldBindJSON(&in)
	if _, known := planPrices[in.Plan]; !known || !validSeats(in.Seats) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "plan is starter|team|enterprise, seats 1-100"})
		return
	}
	cart := Cart{OrgID: user.OrgID, Plan: in.Plan, Seats: in.Seats}
	priceCart(&cart)
	saveCart(c, cart)
}

func applyCoupon(c *gin.Context) {
	cart, ok := adminCart(c)
	if !ok {
		return
	}
	var in struct {
		Code string `json:"code"`
	}
	_ = c.ShouldBindJSON(&in)
	cp, known := coupons[in.Code]
	if !known || !cp.fits(cart.Plan) {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "coupon does not apply to this cart"})
		return
	}
	cart.Coupon = in.Code
	priceCart(&cart)
	saveCart(c, cart)
}

// NM-CART-001: changing the seat count re-prices through priceCart, so the
// coupon is checked again against the cart as it now stands.
func changeSeats(c *gin.Context) {
	cart, ok := adminCart(c)
	if !ok {
		return
	}
	var in struct {
		Seats int `json:"seats"`
	}
	_ = c.ShouldBindJSON(&in)
	if !validSeats(in.Seats) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "seats 1-100"})
		return
	}
	cart.Seats = in.Seats
	priceCart(&cart)
	saveCart(c, cart)
}

func changePlan(c *gin.Context) {
	cart, ok := adminCart(c)
	if !ok {
		return
	}
	var in struct {
		Plan string `json:"plan"`
	}
	_ = c.ShouldBindJSON(&in)
	list, known := planPrices[in.Plan]
	if !known {
		c.JSON(http.StatusBadRequest, gin.H{"error": "plan is starter|team|enterprise"})
		return
	}
	cart.Plan = in.Plan
	// VULN CART-COUPON-001 (CWE-840): the coupon was checked against the plan the
	// cart had when it was applied. Changing the plan afterwards re-prices by hand
	// and carries the discount over without asking whether it still fits - so
	// WELCOME100 (starter only) applied to a starter cart, then a switch to
	// enterprise, checks out enterprise for nothing.
	cart.Price = list * cart.Seats
	if cp, ok := coupons[cart.Coupon]; ok {
		cart.Price = cart.Price * (100 - cp.PercentOff) / 100
	}
	saveCart(c, cart)
}

func checkout(c *gin.Context) {
	cart, ok := adminCart(c)
	if !ok {
		return
	}
	// The card on file is charged exactly what the cart says (simulated).
	ctx := c.Request.Context()
	_, _ = db.ExecContext(ctx, `UPDATE organizations SET plan=$1, paid_cents=paid_cents+$2 WHERE id=$3`, cart.Plan, cart.Price, cart.OrgID)
	_, _ = db.ExecContext(ctx, `DELETE FROM carts WHERE org_id=$1`, cart.OrgID)
	c.JSON(http.StatusOK, gin.H{"plan": cart.Plan, "seats": cart.Seats, "charged_cents": cart.Price})
}

func cancelPlan(c *gin.Context) {
	user, ok := billingAdmin(c)
	if !ok {
		return
	}
	_, _ = db.ExecContext(c.Request.Context(), `UPDATE organizations SET plan='free' WHERE id=$1`, user.OrgID)
	c.JSON(http.StatusOK, gin.H{"plan": "free"})
}
