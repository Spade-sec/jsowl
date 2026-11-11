package main

import (
	"github.com/spf13/cobra"
	"github.com/youmulijiang/jsowl"
	"testing"
)

func TestCertificateFlagOverrides(t *testing.T) {
	for _, tc := range []struct {
		args          []string
		initial, want bool
	}{
		{nil, true, true},
		{[]string{"--ignore-certificate-errors"}, false, true},
		{[]string{"--ignore-certificate-errors=false"}, true, false},
	} {
		var o options
		cmd := &cobra.Command{}
		o.register(cmd.Flags())
		if err := cmd.Flags().Parse(tc.args); err != nil {
			t.Fatal(err)
		}
		cfg := jsowl.DefaultConfig()
		cfg.Browser.IgnoreCertificateErrors = tc.initial
		if err := o.applyOverrides(cmd, &cfg); err != nil {
			t.Fatal(err)
		}
		if cfg.Browser.IgnoreCertificateErrors != tc.want {
			t.Fatalf("args %v: got %v", tc.args, cfg.Browser.IgnoreCertificateErrors)
		}
	}
}
