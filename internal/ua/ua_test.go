package ua

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
)

func TestForTargetHonorsHeaderThenConfiguredUserAgent(t *testing.T) {
	headers := make(http.Header)
	headers.Set("User-Agent", "header-agent")

	got, err := ForTarget("configured-agent", headers, bytes.NewReader([]byte{0, 0}))
	if err != nil {
		t.Fatal(err)
	}
	if got != "header-agent" {
		t.Fatalf("ForTarget header precedence = %q", got)
	}

	headers.Del("User-Agent")
	got, err = ForTarget("configured-agent", headers, bytes.NewReader([]byte{0, 0}))
	if err != nil {
		t.Fatal(err)
	}
	if got != "configured-agent" {
		t.Fatalf("ForTarget configured precedence = %q", got)
	}
}

func TestForTargetSelectsDesktopAgentWhenUnspecified(t *testing.T) {
	headers := make(http.Header)

	first, err := ForTarget("", headers, bytes.NewReader([]byte{0, 0}))
	if err != nil {
		t.Fatal(err)
	}
	second, err := ForTarget("", headers, bytes.NewReader([]byte{1, 0}))
	if err != nil {
		t.Fatal(err)
	}

	if !strings.HasPrefix(first, "Mozilla/5.0") {
		t.Fatalf("first random UA = %q", first)
	}
	if !strings.HasPrefix(second, "Mozilla/5.0") {
		t.Fatalf("second random UA = %q", second)
	}
	if first == second {
		t.Fatalf("random bytes selected identical agents: %q", first)
	}
}
