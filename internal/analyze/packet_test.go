package analyze

import (
	"strings"
	"testing"

	"github.com/youmulijiang/jsowl/internal/model"
)

func ep(raw, method string, spec *model.RequestSpec) *model.Endpoint {
	return &model.Endpoint{Raw: raw, Method: method, Type: "api", Spec: spec}
}

func TestTemplateFormLogin(t *testing.T) {
	// /applet/login 真实形态：URLSearchParams 登录，字面量 code + 运行时字段
	got := RenderPacket(BuildTemplate(ep("/applet/login", "POST", &model.RequestSpec{
		BaseURL:     "/ydzf",
		ContentType: "application/x-www-form-urlencoded",
		ContentTypeEvidence: model.EvidenceLiteral,
		Body: []model.Param{
			{Key: "loginName", Value: "{t.loginName}", Evidence: model.EvidencePlaceholder},
			{Key: "password", Value: "{t.password}", Evidence: model.EvidencePlaceholder},
			{Key: "code", Value: "wx", Evidence: model.EvidenceLiteral},
			{Key: "uuid", Value: "{t.uuid}", Evidence: model.EvidencePlaceholder},
		},
	})))
	want := strings.Join([]string{
		`POST /ydzf/applet/login HTTP/1.1`,
		`Content-Type: application/x-www-form-urlencoded`,
		``,
		`loginName={{fuzz:loginName}}&password={{fuzz:password}}&code=wx&uuid={{fuzz:uuid|token}}`,
	}, "\n")
	if !strings.HasPrefix(got, want) {
		t.Fatalf("form login packet =\n%s\nwant prefix\n%s", got, want)
	}
	if !strings.Contains(got, "# 若站点启用 XSRF 防护") {
		t.Fatalf("missing XSRF note:\n%s", got)
	}
}

func TestTemplateJSONBody(t *testing.T) {
	got := RenderPacket(BuildTemplate(ep("/users/create", "POST", &model.RequestSpec{
		ContentType: "application/json",
		Body: []model.Param{
			{Key: "name", Value: "demo", Evidence: model.EvidenceLiteral},
			{Key: "age", Value: "20", Evidence: model.EvidenceLiteral},
			{Key: "status", Value: "{t.status}", Evidence: model.EvidencePlaceholder},
			{Key: "dept_id", Value: "{t.dept}", Evidence: model.EvidencePlaceholder},
		},
	})))
	want := strings.Join([]string{
		`POST /users/create HTTP/1.1`,
		`Content-Type: application/json`,
		``,
		`{"name":"demo","age":20,"status":"{{fuzz:status}}","dept_id":"{{fuzz:dept_id|id-or}}"}`,
	}, "\n")
	if !strings.HasPrefix(got, want) {
		t.Fatalf("json packet =\n%s\nwant prefix\n%s", got, want)
	}
}

func TestTemplateRuntimeBodyPlaceholder(t *testing.T) {
	// data:t 包装形态：占位符载荷 → {{fuzz:body:t}} + 提示
	got := RenderPacket(BuildTemplate(ep("drug/FeedbackOrAuditSubmit", "POST", &model.RequestSpec{
		BaseURL:     "/ydzf",
		ContentType: "application/json",
		Body:        []model.Param{{Key: "", Value: "{t}", Evidence: model.EvidencePlaceholder}},
	})))
	if !strings.HasPrefix(got, "POST /ydzf/drug/FeedbackOrAuditSubmit HTTP/1.1") {
		t.Fatalf("url join wrong:\n%s", got)
	}
	if !strings.Contains(got, "{{fuzz:body:t}}") {
		t.Fatalf("body placeholder missing:\n%s", got)
	}
	if strings.Contains(got, `"{{fuzz:body:t}}"`) {
		t.Fatalf("placeholder must replace the whole body, not sit inside braces:\n%s", got)
	}
	if !strings.Contains(got, "# 请求体为运行时对象") {
		t.Fatalf("runtime body note missing:\n%s", got)
	}
}

func TestTemplateGetWithQuery(t *testing.T) {
	got := RenderPacket(BuildTemplate(ep("/users/list", "GET", &model.RequestSpec{
		Query: []model.Param{
			{Key: "pageNum", Value: "1", Evidence: model.EvidenceLiteral},
			{Key: "pageSize", Value: "20", Evidence: model.EvidenceLiteral},
			{Key: "keyword", Value: "{t.kw}", Evidence: model.EvidencePlaceholder},
		},
	})))
	want := "GET /users/list?pageNum=1&pageSize=20&keyword={{fuzz:keyword}} HTTP/1.1\n"
	if !strings.HasPrefix(got, want) {
		t.Fatalf("get packet =\n%s\nwant prefix\n%s", got, want)
	}
	if strings.Contains(got, "Content-Type") || strings.Contains(got, "\n\n") {
		t.Fatalf("GET should have no body/content-type:\n%s", got)
	}
}

func TestTemplateFormDataNote(t *testing.T) {
	got := RenderPacket(BuildTemplate(ep("/upload", "POST", &model.RequestSpec{
		ContentType: "multipart/form-data",
		Body:        []model.Param{{Key: "file", Value: "{t.file}", Evidence: model.EvidencePlaceholder}},
	})))
	if strings.Contains(got, "file=") {
		t.Fatalf("multipart should not serialize body pairs:\n%s", got)
	}
	if !strings.Contains(got, "# multipart/form-data 需要真实 boundary；字段: file") {
		t.Fatalf("multipart note missing:\n%s", got)
	}
}

func TestTemplatePasswordNote(t *testing.T) {
	tpl := BuildTemplate(ep("/login", "POST", &model.RequestSpec{
		ContentType: "application/json",
		Body: []model.Param{
			{Key: "username", Value: "{t.user}", Evidence: model.EvidencePlaceholder},
			{Key: "password", Value: "{t.pwd}", Evidence: model.EvidencePlaceholder},
		},
	}))
	packet := RenderPacket(tpl)
	if !strings.Contains(packet, `"password":"{{fuzz:password}}"`) {
		t.Fatalf("password fuzz missing:\n%s", packet)
	}
	if !strings.Contains(packet, "# password 类字段常在客户端做摘要/加密后再发送") {
		t.Fatalf("password transform note missing:\n%s", packet)
	}
}

func TestTemplateSkipsRoutesAndEmpty(t *testing.T) {
	if BuildTemplate(&model.Endpoint{Type: "route", Raw: "/x"}) != nil {
		t.Fatal("route endpoints must not get templates")
	}
	if BuildTemplate(&model.Endpoint{Type: "api", Raw: "   "}) != nil {
		t.Fatal("empty endpoints must not get templates")
	}
}
