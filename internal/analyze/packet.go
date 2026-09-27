package analyze

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/youmulijiang/jsowl/internal/model"
)

// BuildTemplate reconstructs an HTTP request packet from one endpoint's
// recovered spec. Values that the source carried literally are kept verbatim;
// values that only exist at runtime become {{fuzz:...}} placeholders so the
// packet stays copy-paste ready for a fuzzer while never inventing data that
// looks real. nil when the endpoint carries nothing reconstructable.
func BuildTemplate(ep *model.Endpoint) *model.RequestTemplate {
	if ep == nil || ep.Type != "api" {
		return nil
	}
	t := &model.RequestTemplate{Method: ep.Method}
	t.URL = templateURL(ep)
	if t.URL == "" {
		return nil
	}
	if t.Method == "" {
		t.Method = defaultMethod(ep)
	}

	spec := ep.Spec
	if spec != nil {
		if spec.ContentType != "" {
			t.Headers = append(t.Headers, model.HeaderTpl{
				Key: "Content-Type", Value: spec.ContentType, Evidence: spec.ContentTypeEvidence,
			})
		}
		t.Body = templateBody(spec, t.Method, &t.Notes)
	}
	// axios-style clients send the XSRF cookie back as a header on state
	// changing requests; the cookie name is a library default, not a fact
	// about this call site, so it ships as a hint rather than a header line.
	if hasBodyMethod(t.Method) && len(t.Body) > 0 {
		t.Notes = append(t.Notes,
			"若站点启用 XSRF 防护，需携带 X-XSRF-TOKEN: {{cookie:XSRF-TOKEN}}（axios 默认行为，未在调用点确证）")
	}
	// Credential fields are frequently hashed or encrypted client-side; a
	// replay with the plaintext will not match unless the transform is
	// reproduced. The transform itself is only confirmable from the call
	// context, so this stays a note rather than a {{transform:...}} token.
	if spec != nil {
		for _, param := range spec.Body {
			lower := strings.ToLower(param.Key)
			if strings.Contains(lower, "password") || strings.Contains(lower, "pwd") {
				t.Notes = append(t.Notes,
					"password 类字段常在客户端做摘要/加密后再发送，重放前请核对调用点上下文中的变换函数")
				break
			}
		}
	}
	if len(t.Headers) == 0 && len(t.Body) == 0 && len(t.Notes) == 0 {
		// A bare GET is still a valid packet; nothing extra to add.
	}
	sortHeaders(t.Headers)
	return t
}
// templateURL joins the recovered base URL with the endpoint path and appends
// the spec's query parameters. Query values follow the same literal-first
// policy as the body: a literal value ships as-is, a runtime one becomes a
// fuzz placeholder.
func templateURL(ep *model.Endpoint) string {
	raw := strings.TrimSpace(ep.Raw)
	if raw == "" {
		raw = strings.TrimSpace(ep.URL)
	}
	if raw == "" {
		return ""
	}
	if raw != "" && (strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://")) {
		// Absolute endpoints keep their URL; query params would duplicate
		// what the URL already carries.
		return raw
	}
	base := ""
	if ep.Spec != nil && ep.Spec.BaseURL != "" {
		base = strings.TrimRight(ep.Spec.BaseURL, "/")
	}
	full := base + "/" + strings.TrimLeft(raw, "/")
	if ep.Spec != nil && len(ep.Spec.Query) > 0 && !strings.Contains(full, "?") {
		full += "?" + serializePairs(ep.Spec.Query, false)
	}
	return full
}

// defaultMethod picks a verb when the call site did not record one: body
// parameters imply POST, anything else is a GET.
func defaultMethod(ep *model.Endpoint) string {
	if ep.Spec != nil && len(ep.Spec.Body) > 0 {
		return "POST"
	}
	return "GET"
}

// templateBody serializes the spec's body parameters into the wire format the
// content type implies. Query parameters never land here — they are part of
// the URL line.
func templateBody(spec *model.RequestSpec, method string, notes *[]string) string {
	if !hasBodyMethod(method) || len(spec.Body) == 0 {
		return ""
	}
	contentType := strings.ToLower(spec.ContentType)
	switch {
	case strings.Contains(contentType, "json"):
		return serializeJSON(spec.Body, notes)
	case strings.Contains(contentType, "urlencoded"):
		return serializePairs(spec.Body, true)
	case strings.Contains(contentType, "form-data"):
		fields := make([]string, 0, len(spec.Body))
		for _, param := range spec.Body {
			if param.Key == "" {
				continue
			}
			fields = append(fields, param.Key)
		}
		*notes = append(*notes,
			"multipart/form-data 需要真实 boundary；字段: "+strings.Join(fields, ", "))
		return ""
	default:
		// Unknown content type: form-style serialization is the least
		// surprising default for key=value pairs.
		return serializePairs(spec.Body, true)
	}
}

// serializeJSON renders body parameters as a JSON object. Literal values are
// typed correctly (numbers bare, strings quoted); placeholder values stay
// strings — a fuzzer replaces the whole {{fuzz:...}} token anyway. A keyless
// placeholder replaces the ENTIRE body: the payload is one runtime object,
// so wrapping the token in an object with a fake key would produce invalid
// and misleading JSON.
func serializeJSON(params []model.Param, notes *[]string) string {
	for _, param := range params {
		if param.Key == "" && param.Evidence == model.EvidencePlaceholder {
			symbol := strings.Trim(param.Value, "{}")
			*notes = append(*notes,
				"请求体为运行时对象（源码符号 "+symbol+"），字段需动态确认")
			return "{{fuzz:body:" + symbol + "}}"
		}
	}
	parts := make([]string, 0, len(params))
	for _, param := range params {
		if param.Key == "" {
			continue
		}
		value, _ := bodyValue(param)
		if isJSONNumber(param.Value) {
			parts = append(parts, strconv.Quote(param.Key)+":"+param.Value)
			continue
		}
		if param.Value == "true" || param.Value == "false" || param.Value == "null" {
			parts = append(parts, strconv.Quote(param.Key)+":"+param.Value)
			continue
		}
		parts = append(parts, strconv.Quote(param.Key)+":"+strconv.Quote(value))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// serializePairs renders parameters as key=value pairs joined by &.
func serializePairs(params []model.Param, allowEmptyKeyNote bool) string {
	parts := make([]string, 0, len(params))
	for _, param := range params {
		if param.Key == "" {
			if allowEmptyKeyNote {
				parts = append(parts, "{{fuzz:body:"+strings.Trim(param.Value, "{}")+"}}")
			}
			continue
		}
		parts = append(parts, param.Key+"="+bodyValueText(param))
	}
	return strings.Join(parts, "&")
}

// bodyValue returns the wire value for one parameter: the literal value when
// the source had one, otherwise a {{fuzz:...}} placeholder derived from the
// key's semantics.
func bodyValue(param model.Param) (string, bool) {
	switch param.Evidence {
	case model.EvidenceLiteral, model.EvidenceConstant:
		if param.Value != "" && param.Value != "{}" {
			return param.Value, false
		}
	case model.EvidenceRuntime:
		if param.Value != "" {
			return param.Value, false
		}
	}
	return "{{fuzz:" + fuzzTag(param.Key) + "}}", true
}

// bodyValueText is bodyValue for pair serialization (no extra quoting).
func bodyValueText(param model.Param) string {
	value, _ := bodyValue(param)
	return value
}

// fuzzTag derives a placeholder name from the parameter key. The tag keeps
// the original key so a fuzzer knows what it is replacing; special-cased
// prefixes hint at the expected value class. The token check runs before the
// id check: "uuid" ends in "id" but is a session token, not a row id.
func fuzzTag(key string) string {
	lower := strings.ToLower(key)
	switch {
	case strings.Contains(lower, "token") || strings.Contains(lower, "uuid") || strings.Contains(lower, "captcha"):
		return key + "|token"
	case strings.HasSuffix(lower, "id") || strings.HasSuffix(lower, "_no") || strings.HasSuffix(lower, "no"):
		return key + "|id-or"
	case strings.Contains(lower, "page"):
		return key + "|num"
	default:
		return key
	}
}

// hasBodyMethod reports whether the verb carries a request body.
func hasBodyMethod(method string) bool {
	switch strings.ToUpper(method) {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	}
	return false
}

// isJSONNumber reports whether the value can sit unquoted in a JSON body.
func isJSONNumber(value string) bool {
	if value == "" {
		return false
	}
	_, err := strconv.ParseFloat(value, 64)
	return err == nil
}

// sortHeaders keeps header order deterministic: Content-Type first, then
// alphabetical — the same packet always renders identically.
func sortHeaders(headers []model.HeaderTpl) {
	sort.SliceStable(headers, func(i, j int) bool {
		if (headers[i].Key == "Content-Type") != (headers[j].Key == "Content-Type") {
			return headers[i].Key == "Content-Type"
		}
		return headers[i].Key < headers[j].Key
	})
}

// RenderPacket formats a template as raw HTTP text — the copy-paste form
// shown in the report.
func RenderPacket(t *model.RequestTemplate) string {
	if t == nil {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\n", t.Method, t.URL)
	for _, header := range t.Headers {
		fmt.Fprintf(&b, "%s: %s\n", header.Key, header.Value)
	}
	if t.Body != "" {
		b.WriteString("\n")
		b.WriteString(t.Body)
		b.WriteString("\n")
	}
	for _, note := range t.Notes {
		b.WriteString("\n# " + note)
	}
	return strings.TrimRight(b.String(), "\n") + "\n"
}
