package discover

import (
	"strings"
	"testing"
)

func TestIsThirdPartyBundleReadsLicenseBanner(t *testing.T) {
	jquery := []byte("/*! jQuery JavaScript Library v3.6.0\n * https://jquery.org/\n * Copyright OpenJS Foundation\n * Released under the MIT license\n */\n!function(e,t){}(window);")
	if !IsThirdPartyBundle(jquery) {
		t.Fatal("jquery banner was not detected as third-party")
	}

	// Application bundles are hand-written code without an upstream banner.
	app := []byte("import{a}from'./x';const t={url:\"/soap/init\",method:\"post\"};export default t;")
	if IsThirdPartyBundle(app) {
		t.Fatal("application bundle was misdetected as third-party")
	}

	// A banner that names no known library stays analysed: better to parse it
	// than to silently drop a bundle that might carry real endpoints.
	unknown := []byte("/*! my-corp internal bundle */\nvar a=1;")
	if IsThirdPartyBundle(unknown) {
		t.Fatal("unrecognised banner treated as a library")
	}
}

func TestLicenseBannerFindsLineCommentForm(t *testing.T) {
	body := []byte("var a=1;\n// Copyright 2024 Example Inc.\n// @license MIT\n// trailing note\nvar b=2;")
	banner := LicenseBanner(body)
	if banner == "" {
		t.Fatal("line-comment license banner not found")
	}
	for _, want := range []string{"@license", "Copyright"} {
		if !strings.Contains(banner, want) {
			t.Errorf("banner missing %q: %q", want, banner)
		}
	}
}
