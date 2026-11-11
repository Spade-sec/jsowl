// Package aiclient is a minimal client for the AI upstream protocols jsowl
// supports: OpenAI Chat Completions, OpenAI Responses, Anthropic Messages
// (native) and Gemini generateContent (native).
package aiclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Upstream formats accepted by ai.format in the configuration. Aliases are
// resolved by NormalizeFormat.
const (
	FormatOpenAIChat      = "openai-chat"
	FormatOpenAIResponses = "openai-responses"
	FormatAnthropic       = "anthropic-messages"
	FormatGemini          = "gemini-native"
)

// formatAliases maps the documented shorthand names onto canonical formats.
var formatAliases = map[string]string{
	"openai":                  FormatOpenAIChat,
	"openai-chat":             FormatOpenAIChat,
	"openai-chat-completion":  FormatOpenAIChat,
	"openai-chat-completions": FormatOpenAIChat,
	"openai-responses":        FormatOpenAIResponses,
	"anthropic":               FormatAnthropic,
	"anthropic-messages":      FormatAnthropic,
	"gemini":                  FormatGemini,
	"gemini-native":           FormatGemini,
}

// NormalizeFormat resolves a configured ai.format value to its canonical
// name; an empty or unknown value falls back to the OpenAI Chat Completions
// default that earlier jsowl versions always used.
func NormalizeFormat(format string) string {
	if canonical, ok := formatAliases[strings.ToLower(strings.TrimSpace(format))]; ok {
		return canonical
	}
	return FormatOpenAIChat
}

// Client posts chat turns against one configured provider and format.
type Client struct {
	BaseURL string // provider root, no trailing slash
	APIKey  string
	Model   string
	Format  string // canonical upstream format, see NormalizeFormat
	HTTP    *http.Client
}

// ChatOptions tweaks a single chat turn. Zero-value options keep the
// provider defaults, which is what the fast enrichers want.
type ChatOptions struct {
	// Temperature, when set, is sent as the sampling temperature. The
	// analysis layers pass 0: verdicts should be reproducible, not creative.
	Temperature *float64
	// JSONMode asks the upstream to constrain its reply to valid JSON where
	// the protocol supports it (OpenAI response_format, Gemini
	// responseMimeType, Anthropic assistant prefill). Protocols without
	// native support keep prompt-level instruction only.
	JSONMode bool
}

// chatTurn is the protocol-neutral payload one Chat turn encodes to.
type chatTurn struct {
	system string
	user   string
	opts   ChatOptions
	// anthropicPrefill marks that JSONMode was expressed as an assistant
	// prefill: the reply continues the prefaced "{" so it must be
	// re-attached after decoding.
	anthropicPrefill bool
}

// New builds a client; the format is normalized to a supported protocol and
// the HTTP timeout is 60s.
func New(baseURL, apiKey, model, format string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		APIKey:  apiKey,
		Model:   model,
		Format:  NormalizeFormat(format),
		HTTP:    &http.Client{Timeout: 60 * time.Second},
	}
}

// Chat sends one system+user turn with provider-default sampling and returns
// the assistant content. One retry on transport errors and 5xx/429, so a
// flaky gateway does not fail a scan; 4xx (auth, quota) fails fast —
// retrying cannot help.
func (c *Client) Chat(ctx context.Context, system, user string) (string, error) {
	return c.ChatWithOptions(ctx, system, user, ChatOptions{})
}

// ChatWithOptions sends one system+user turn under the given options.
// Retry semantics match Chat; a 429 reply delays the retry by its
// Retry-After header (capped) instead of the fixed backoff.
func (c *Client) ChatWithOptions(ctx context.Context, system, user string, opts ChatOptions) (string, error) {
	turn := chatTurn{system: system, user: user, opts: opts}
	// Anthropic expresses JSONMode as an assistant prefill; the reply then
	// continues the prefaced "{" and must be re-completed after decoding.
	turn.anthropicPrefill = opts.JSONMode && c.Format == FormatAnthropic
	payload, err := c.encodeRequest(turn)
	if err != nil {
		return "", fmt.Errorf("ai request encode: %w", err)
	}
	url := c.endpoint()
	var lastErr error
	nextDelay := time.Second
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(nextDelay):
			}
		}
		content, retryable, retryAfter, err := c.once(ctx, url, payload)
		if err == nil {
			if turn.anthropicPrefill {
				content = "{" + content
			}
			return content, nil
		}
		lastErr = err
		if !retryable {
			return "", err
		}
		if retryAfter > 0 {
			nextDelay = retryAfter
		}
	}
	return "", lastErr
}

// endpoint resolves the request URL for the configured format. Bases that
// already carry a version segment are not double-prefixed, so both
// https://host and https://host/v1 (or /v1beta for Gemini) work.
func (c *Client) endpoint() string {
	base := strings.TrimRight(c.BaseURL, "/")
	switch c.Format {
	case FormatAnthropic:
		if strings.HasSuffix(base, "/v1") {
			return base + "/messages"
		}
		return base + "/v1/messages"
	case FormatOpenAIResponses:
		if strings.HasSuffix(base, "/v1") {
			return base + "/responses"
		}
		return base + "/v1/responses"
	case FormatGemini:
		if strings.HasSuffix(base, "/v1beta") {
			return base + "/models/" + c.Model + ":generateContent"
		}
		return base + "/v1beta/models/" + c.Model + ":generateContent"
	default:
		return base + "/chat/completions"
	}
}

// maxReplyTokens caps Anthropic's mandatory max_tokens and the other
// protocols' equivalent output budget; the enrichers ask for short verdicts.
const maxReplyTokens = 4096

// encodeRequest builds the wire payload for the configured format. Options
// the protocol cannot express are dropped rather than approximated: the
// prompt already demands strict JSON.
func (c *Client) encodeRequest(turn chatTurn) ([]byte, error) {
	temperature := turn.opts.Temperature
	jsonMode := turn.opts.JSONMode
	switch c.Format {
	case FormatAnthropic:
		messages := []map[string]any{
			{"role": "user", "content": turn.user},
		}
		if jsonMode {
			// Anthropic has no JSON schema constraint; a one-character
			// assistant prefill steers the reply into a JSON object, which
			// ChatWithOptions re-completes after decoding.
			messages = append(messages, map[string]any{"role": "assistant", "content": "{"})
		}
		payload := map[string]any{
			"model":      c.Model,
			"max_tokens": maxReplyTokens,
			"system":     turn.system,
			"messages":   messages,
		}
		if temperature != nil {
			payload["temperature"] = *temperature
		}
		return json.Marshal(payload)
	case FormatOpenAIResponses:
		payload := map[string]any{
			"model": c.Model,
			"input": []map[string]any{
				{"role": "system", "content": turn.system},
				{"role": "user", "content": turn.user},
			},
			"max_output_tokens": maxReplyTokens,
		}
		if temperature != nil {
			payload["temperature"] = *temperature
		}
		if jsonMode {
			payload["text"] = map[string]any{
				"format": map[string]any{"type": "json_object"},
			}
		}
		return json.Marshal(payload)
	case FormatGemini:
		generation := map[string]any{"maxOutputTokens": maxReplyTokens}
		if temperature != nil {
			generation["temperature"] = *temperature
		}
		if jsonMode {
			generation["responseMimeType"] = "application/json"
		}
		return json.Marshal(map[string]any{
			"system_instruction": map[string]any{
				"parts": []map[string]any{{"text": turn.system}},
			},
			"contents": []map[string]any{
				{"role": "user", "parts": []map[string]any{{"text": turn.user}}},
			},
			"generationConfig": generation,
		})
	default:
		payload := map[string]any{
			"model": c.Model,
			"messages": []map[string]any{
				{"role": "system", "content": turn.system},
				{"role": "user", "content": turn.user},
			},
		}
		if temperature != nil {
			payload["temperature"] = *temperature
		}
		if jsonMode {
			payload["response_format"] = map[string]any{"type": "json_object"}
		}
		return json.Marshal(payload)
	}
}

// applyAuth sets the credential header the configured format expects.
func (c *Client) applyAuth(req *http.Request) {
	switch c.Format {
	case FormatAnthropic:
		req.Header.Set("x-api-key", c.APIKey)
		req.Header.Set("anthropic-version", "2023-06-01")
	case FormatGemini:
		req.Header.Set("x-goog-api-key", c.APIKey)
	default:
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}
}

// decodeResponse extracts the assistant text from one format's reply body.
func (c *Client) decodeResponse(body []byte) (string, error) {
	switch c.Format {
	case FormatAnthropic:
		var parsed struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
			Error *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(body, &parsed); err != nil {
			return "", fmt.Errorf("ai response parse: %w", err)
		}
		if parsed.Error != nil && parsed.Error.Message != "" {
			return "", fmt.Errorf("ai provider error: %s", parsed.Error.Message)
		}
		var text strings.Builder
		for _, block := range parsed.Content {
			if block.Type == "text" {
				text.WriteString(block.Text)
			}
		}
		if text.Len() == 0 {
			return "", fmt.Errorf("ai response has no text content")
		}
		return text.String(), nil
	case FormatOpenAIResponses:
		var parsed struct {
			Output []struct {
				Type    string `json:"type"`
				Content []struct {
					Type string `json:"type"`
					Text string `json:"text"`
				} `json:"content"`
			} `json:"output"`
			Error *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(body, &parsed); err != nil {
			return "", fmt.Errorf("ai response parse: %w", err)
		}
		if parsed.Error != nil && parsed.Error.Message != "" {
			return "", fmt.Errorf("ai provider error: %s", parsed.Error.Message)
		}
		var text strings.Builder
		for _, item := range parsed.Output {
			for _, block := range item.Content {
				if block.Type == "output_text" {
					text.WriteString(block.Text)
				}
			}
		}
		if text.Len() == 0 {
			return "", fmt.Errorf("ai response has no output text")
		}
		return text.String(), nil
	case FormatGemini:
		var parsed struct {
			Candidates []struct {
				Content struct {
					Parts []struct {
						Text string `json:"text"`
					} `json:"parts"`
				} `json:"content"`
			} `json:"candidates"`
			Error *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(body, &parsed); err != nil {
			return "", fmt.Errorf("ai response parse: %w", err)
		}
		if parsed.Error != nil && parsed.Error.Message != "" {
			return "", fmt.Errorf("ai provider error: %s", parsed.Error.Message)
		}
		var text strings.Builder
		for _, candidate := range parsed.Candidates {
			for _, part := range candidate.Content.Parts {
				text.WriteString(part.Text)
			}
		}
		if text.Len() == 0 {
			return "", fmt.Errorf("ai response has no candidate text")
		}
		return text.String(), nil
	default:
		var parsed struct {
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"choices"`
			Error *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(body, &parsed); err != nil {
			return "", fmt.Errorf("ai response parse: %w", err)
		}
		if parsed.Error != nil && parsed.Error.Message != "" {
			return "", fmt.Errorf("ai provider error: %s", parsed.Error.Message)
		}
		if len(parsed.Choices) == 0 {
			return "", fmt.Errorf("ai response has no choices")
		}
		return parsed.Choices[0].Message.Content, nil
	}
}

// maxRetryAfter caps the Retry-After wait a 429 reply may impose: an
// unreasonable or malicious upstream cannot stall a scan for minutes.
const maxRetryAfter = 30 * time.Second

func (c *Client) once(ctx context.Context, url string, payload []byte) (content string, retryable bool, retryAfter time.Duration, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return "", false, 0, fmt.Errorf("ai request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	c.applyAuth(req)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", true, 0, fmt.Errorf("ai transport: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", true, 0, fmt.Errorf("ai response read: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		message := strings.TrimSpace(string(body))
		if len(message) > 300 {
			message = message[:300]
		}
		// 429 is rate limiting, not a configuration error: one retry after
		// the server's own hint is the difference between a working scan and
		// a failed one against metered gateways.
		retryable = resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		return "", retryable, parseRetryAfter(resp.Header.Get("Retry-After")), fmt.Errorf("ai http %d: %s", resp.StatusCode, message)
	}
	content, decodeErr := c.decodeResponse(body)
	return content, false, 0, decodeErr
}

// parseRetryAfter reads a numeric Retry-After header (seconds); a missing,
// non-numeric or out-of-range value yields 0 so the caller keeps its
// default backoff.
func parseRetryAfter(value string) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	seconds, err := strconv.Atoi(value)
	if err != nil || seconds <= 0 {
		return 0
	}
	delay := time.Duration(seconds) * time.Second
	if delay > maxRetryAfter {
		return maxRetryAfter
	}
	return delay
}
