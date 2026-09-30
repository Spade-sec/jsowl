package browser

import (
	"testing"

	"github.com/go-rod/rod/lib/proto"
)

func TestCookiesToParamsPreservesScopeAndAttributes(t *testing.T) {
	t.Parallel()
	expires := proto.TimeSinceEpoch(1893456000) // 2030-01-01
	cookies := []*proto.NetworkCookie{
		{
			Name: "session", Value: "abc", Domain: ".example.com", Path: "/",
			Secure: true, HTTPOnly: true,
			SameSite: proto.NetworkCookieSameSiteLax,
			Expires:  expires, Session: false,
		},
		{
			Name: "flash", Value: "x", Domain: "example.com", Path: "/app",
			Session: true,
		},
		{Name: "", Value: "dropped"},
	}
	params := cookiesToParams(cookies)
	if len(params) != 2 {
		t.Fatalf("params = %d entries, want 2 (empty names dropped)", len(params))
	}
	session := params[0]
	if session.Domain != ".example.com" || session.Path != "/" ||
		!session.Secure || !session.HTTPOnly ||
		session.SameSite != proto.NetworkCookieSameSiteLax {
		t.Fatalf("session cookie attributes lost: %+v", session)
	}
	if session.Expires != expires {
		t.Fatalf("persistent cookie lost its expiry: %+v", session)
	}
	flash := params[1]
	if flash.Domain != "example.com" || flash.Path != "/app" {
		t.Fatalf("flash cookie scope lost: %+v", flash)
	}
	if flash.Expires != 0 {
		t.Fatalf("session cookie must stay session-scoped: %+v", flash)
	}
}
