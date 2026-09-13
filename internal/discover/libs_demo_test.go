package discover

import (
	"net/url"
	"os"
	"strings"
	"testing"
)

func TestExtractRequestLibrariesFixture(t *testing.T) {
	body, err := os.ReadFile("testdata/request_libs.js")
	if err != nil {
		t.Fatal(err)
	}
	source, _ := url.Parse("https://demo.example.test/app.js")
	candidates := APIFromAST(source, body)
	byURL := map[string]*Candidate{}
	for i := range candidates {
		byURL[candidates[i].Raw] = &candidates[i]
	}

	cases := []struct {
		url        string
		method     string
		bodyParams string // comma-joined, "" = none expected
	}{
		{"/login", "POST", "username,password"},
		{"/user/list?page=2&size=20", "GET", ""},
		{"/v1/items?sort=desc", "GET", ""},
		{"https://api.example.test/v1/orders", "POST", "sku,count"},
		{"https://gw.example.test/v1/ping", "POST", "echo"},
		{"/api/session", "POST", "token"},
		{"https://api.example.test/v2/profile?uid=8", "GET", ""},
		{"/legacy/list?catid=7", "GET", ""},
		{"/legacy/save", "POST", "title,status"},
		{"/legacy/detail?id=9", "PUT", "remark"},
		{"https://api.weixin.example.test/pay/create", "POST", "openid,amount"},
		{"/uni/user/info", "GET", "uid"},
		{"https://api.example.test/v1/notes", "POST", "title,content"},
		{"/v1/cache?key=static", "DELETE", ""},
		{"/umix/list?state=open", "GET", ""},
		{"https://api.example.test/umix/submit", "POST", "formId"},
		{"/alova/config?section=mail", "GET", ""},
		{"https://api.example.test/alova/upload", "POST", "fileKey"},
		{"/wretch/cart?uid=3", "POST", "sku"},
		{"https://api.example.test/wretch/checkout", "PUT", "address"},
		{"/swr/session?fields=all", "GET", ""},
	}
	for _, want := range cases {
		got := byURL[want.url]
		if got == nil {
			t.Errorf("missing %s", want.url)
			continue
		}
		if got.Method != want.method {
			t.Errorf("%s method = %s, want %s", want.url, got.Method, want.method)
		}
		if strings.Join(got.BodyParams, ",") != want.bodyParams {
			t.Errorf("%s body params = %v, want [%s]", want.url, got.BodyParams, want.bodyParams)
		}
	}
}
