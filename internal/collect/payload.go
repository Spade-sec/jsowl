package collect

import (
	"encoding/json"
	"net/url"
	"strconv"
	"strings"

	"github.com/youmulijiang/jsowl/internal/model"
)

// maxRuntimeParams caps how many parameters one observed request contributes.
const maxRuntimeParams = 32

// runtimeValueLimit truncates one observed parameter value: runtime values
// are real user data, so they are kept short — enough to type the field,
// never a full token or document.
const runtimeValueLimit = 64

// ParseRequestPayload turns one browser-observed request into a RequestSpec:
// query parameters from the URL and body parameters from the POST payload,
// every value carrying runtime evidence because it was sent by the real
// application. nil when the request carries nothing usable.
func ParseRequestPayload(method, rawURL, postData, contentType string) *model.RequestSpec {
	spec := &model.RequestSpec{}
	if parsed, err := url.Parse(rawURL); err == nil {
		for key, values := range parsed.Query() {
			if len(spec.Query) >= maxRuntimeParams {
				break
			}
			value := ""
			if len(values) > 0 {
				value = values[0]
			}
			spec.Query = append(spec.Query, model.Param{
				Key: key, Value: truncateValue(value), Evidence: model.EvidenceRuntime,
			})
		}
	}
	if postData == "" {
		if len(spec.Query) == 0 {
			return nil
		}
		return spec
	}
	contentType = strings.ToLower(contentType)
	switch {
	case strings.Contains(contentType, "json"), looksLikeJSON(postData):
		spec.Body = jsonPayloadParams(postData, spec.Body)
		if strings.Contains(spec.ContentType, "json") || spec.ContentType == "" {
			if contentType != "" {
				spec.ContentType, spec.ContentTypeEvidence = contentType, model.EvidenceRuntime
			} else {
				spec.ContentType, spec.ContentTypeEvidence = "application/json", model.EvidenceRuntime
			}
		}
	case strings.Contains(contentType, "multipart/form-data"):
		spec.Body = formParams(postData, spec.Body)
		spec.ContentType, spec.ContentTypeEvidence = contentType, model.EvidenceRuntime
	case strings.Contains(contentType, "x-www-form-urlencoded"),
		strings.Contains(postData, "=") && !strings.HasPrefix(strings.TrimSpace(postData), "{"):
		spec.Body = formParams(postData, spec.Body)
		if contentType != "" {
			spec.ContentType, spec.ContentTypeEvidence = contentType, model.EvidenceRuntime
		}
	}
	if len(spec.Query) == 0 && len(spec.Body) == 0 {
		return nil
	}
	return spec
}

// jsonPayloadParams flattens a JSON request body into dotted keys, mirroring
// the AST extraction shape so both sources merge cleanly. Array elements
// dedupe by key, so ten list rows still yield one row per distinct field.
func jsonPayloadParams(postData string, base []model.Param) []model.Param {
	trimmed := strings.TrimSpace(postData)
	if !json.Valid([]byte(trimmed)) {
		return base
	}
	var payload any
	if err := json.Unmarshal([]byte(trimmed), &payload); err != nil {
		return base
	}
	return appendRuntimeParams(base, jsonParams("", payload, 0))
}

func jsonParams(prefix string, value any, depth int) []model.Param {
	if depth > 3 {
		return nil
	}
	switch typed := value.(type) {
	case map[string]any:
		params := make([]model.Param, 0, len(typed))
		for key, child := range typed {
			name := key
			if prefix != "" {
				name = prefix + "." + key
			}
			params = append(params, jsonParams(name, child, depth+1)...)
		}
		return params
	case []any:
		name := prefix + "[]"
		if prefix == "" {
			name = "[]"
		}
		params := make([]model.Param, 0, len(typed))
		for _, element := range typed {
			params = appendRuntimeParams(params, jsonParams(name, element, depth+1))
		}
		return params
	default:
		if prefix == "" {
			return nil
		}
		return []model.Param{{
			Key: prefix, Value: truncateValue(scalarText(value)),
			Evidence: model.EvidenceRuntime,
		}}
	}
}

// formParams reads form-urlencoded and multipart bodies: both are flat
// key/value or key/filename shapes, so only the keys and a short sample of
// the first value per key are useful.
func formParams(postData string, base []model.Param) []model.Param {
	values, err := url.ParseQuery(postData)
	if err != nil || len(values) == 0 {
		return base
	}
	for key, list := range values {
		if len(base) >= maxRuntimeParams {
			break
		}
		value := ""
		if len(list) > 0 {
			value = list[0]
		}
		base = appendRuntimeParams(base, []model.Param{{
			Key: key, Value: truncateValue(value), Evidence: model.EvidenceRuntime,
		}})
	}
	return base
}

func looksLikeJSON(postData string) bool {
	trimmed := strings.TrimSpace(postData)
	return strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")
}

func appendRuntimeParams(base, extra []model.Param) []model.Param {
	seen := make(map[string]struct{}, len(base)+len(extra))
	for _, param := range base {
		seen[param.Key] = struct{}{}
	}
	for _, param := range extra {
		if param.Key == "" || len(base) >= maxRuntimeParams {
			continue
		}
		if _, duplicate := seen[param.Key]; duplicate {
			continue
		}
		seen[param.Key] = struct{}{}
		base = append(base, param)
	}
	return base
}

func scalarText(value any) string {
	switch typed := value.(type) {
	case nil:
		return "null"
	case string:
		return typed
	case bool:
		return strconv.FormatBool(typed)
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	default:
		return ""
	}
}

func truncateValue(value string) string {
	if len(value) <= runtimeValueLimit {
		return value
	}
	return value[:runtimeValueLimit] + "…"
}
