package discover

import (
	"testing"
)

// The AST pass exists for runtime spellings the regex pass cannot match:
// plain functions, template strings and subscript property access.

func TestWebpackASTPlainFunctionRuntime(t *testing.T) {
	body := []byte(`var r={};r.u=function(e){return "static/js/"+e+"."+{1:"a1b2",21:"c3d4"}[e]+".js"},r.p="https://cdn.test/app/";`)
	_, filenames := webpackASTExtract(body)
	want := []string{"static/js/1.a1b2.js", "static/js/21.c3d4.js"}
	if len(filenames) != len(want) {
		t.Fatalf("filenames = %v, want %v", filenames, want)
	}
	for i, name := range want {
		if filenames[i] != name {
			t.Fatalf("filenames[%d] = %q, want %q", i, filenames[i], name)
		}
	}
}

func TestWebpackASTTemplateStringRuntime(t *testing.T) {
	body := []byte("__webpack_require__.u=e=>`${e}.${{1:\"a1b2\",21:\"c3d4\"}[e]}.js`;")
	_, filenames := webpackASTExtract(body)
	if len(filenames) != 2 || filenames[0] != "1.a1b2.js" || filenames[1] != "21.c3d4.js" {
		t.Fatalf("filenames = %v", filenames)
	}
}

func TestWebpackASTSubscriptPropertyAccess(t *testing.T) {
	body := []byte(`r["u"]=e=>"js/"+e+"."+{3:"x9y8"}[e]+".js";`)
	_, filenames := webpackASTExtract(body)
	if len(filenames) != 1 || filenames[0] != "js/3.x9y8.js" {
		t.Fatalf("filenames = %v", filenames)
	}
}

func TestWebpackASTPublicPathFromTemplate(t *testing.T) {
	body := []byte("r.p=`https://cdn.test/app/`;r.u=e=>`${e}.${{7:\"k2l3\"}[e]}.js`;")
	publicPath, _ := webpackASTExtract(body)
	if publicPath != "https://cdn.test/app/" {
		t.Fatalf("publicPath = %q", publicPath)
	}
}

func TestWebpackASTIgnoresNonWebpackBody(t *testing.T) {
	_, filenames := webpackASTExtract([]byte(`var total={a:1,b:2};fetch("/api/users");`))
	if len(filenames) != 0 {
		t.Fatalf("filenames = %v, want none", filenames)
	}
}

func TestWebpackASTJoinExpression(t *testing.T) {
	body := []byte(`r.u=e=>["js/",e+".",({1:"m4n5"})[e],".js"].join("");`)
	_, filenames := webpackASTExtract(body)
	if len(filenames) != 1 || filenames[0] != "js/1.m4n5.js" {
		t.Fatalf("filenames = %v", filenames)
	}
}

// The FromWebpack entry unions the regex and AST passes: each scenario below
// was invisible to exactly one of them before.
func TestFromWebpackUnionsRegexAndASTResults(t *testing.T) {
	source := mustParseURL(t, "https://example.test/assets/runtime.js")

	// AST-only: plain function runtime, which the .u regex matcher skips.
	plainFunction := []byte(`webpackChunk.callback;r.u=function(e){return "js/"+e+"."+{9:"z1z2"}[e]+".js"};`)
	got := FromWebpack(source, plainFunction, 100)
	assertCandidate(t, got, "https://example.test/assets/js/9.z1z2.js", KindChunk)

	// Regex-only output is preserved alongside the AST pass: the classic
	// arrow-function runtime must still produce the same candidates.
	arrow := []byte(`webpackChunk;r.u=e=>"js/"+e+"."+{9:"z1z2"}[e]+".js";`)
	got = FromWebpack(source, arrow, 100)
	assertCandidate(t, got, "https://example.test/assets/js/9.z1z2.js", KindChunk)
}

func TestWebpackASTConcatChain(t *testing.T) {
	body := []byte(`r.u=function(e){return "js/".concat(e).concat(".").concat({5:"p6q7"}[e]).concat(".js")};`)
	_, filenames := webpackASTExtract(body)
	if len(filenames) != 1 || filenames[0] != "js/5.p6q7.js" {
		t.Fatalf("filenames = %v", filenames)
	}
}

func TestWebpackASTDefinePropertyRuntime(t *testing.T) {
	body := []byte(`Object.defineProperty(r,"u",{value:function(e){return "js/"+e+"."+{4:"w8x9"}[e]+".js"}});`)
	_, filenames := webpackASTExtract(body)
	if len(filenames) != 1 || filenames[0] != "js/4.w8x9.js" {
		t.Fatalf("filenames = %v", filenames)
	}
}

// A map-less runtime names chunks by id alone; the ids only appear at the
// .e(<id>) call sites, so the AST pass must collect them there.
func TestWebpackASTEnumeratesLazyLoadCallSites(t *testing.T) {
	body := []byte(`__webpack_require__.p="static/js/";__webpack_require__.u=e=>"js/"+e+".js";__webpack_require__.e(11);__webpack_require__.e("vendors");r.e(42);`)
	_, filenames := webpackASTExtract(body)
	want := []string{"js/11.js", "js/vendors.js", "js/42.js"}
	if len(filenames) != len(want) {
		t.Fatalf("filenames = %v, want %v", filenames, want)
	}
	for i, name := range want {
		if filenames[i] != name {
			t.Fatalf("filenames[%d] = %q, want %q", i, filenames[i], name)
		}
	}
}
