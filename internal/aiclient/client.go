// Package aiclient is a minimal OpenAI-compatible chat completions client.
// Any provider exposing that protocol works — GLM, one-api proxies, vLLM.
package aiclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client posts chat completions against one configured provider.
type Client struct {
	BaseURL string // provider root, no trailing slash
	APIKey  string
	Model   string
	Path    string // chat completions route, default /chat/completions
	HTTP    *http.Client
}

// New builds a client with sane defaults; empty Path falls back to
// /chat/completions and the HTTP timeout is 60s.
func New(baseURL, apiKey, model, path string) *Client {
	if path == "" {
		path = "/chat/completions"
	}
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		APIKey:  apiKey,
		Model:   model,
		Path:    path,
		HTTP:    &http.Client{Timeout: 60 * time.Second},
	}
}

// chatRequest is the OpenAI-compatible payload (only the fields used).
type chatRequest struct {
	Model    string        `json:"model"`
	Messages []chatMessage `json:"messages"`
}
type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}
type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// Chat sends one system+user turn and returns the assistant content.
// One retry on transport errors and 5xx, so a flaky gateway does not fail a
// scan; 4xx (auth, quota) fails fast — retrying cannot help.
func (c *Client) Chat(ctx context.Context, system, user string) (string, error) {
	payload, err := json.Marshal(chatRequest{
		Model: c.Model,
		Messages: []chatMessage{
			{Role: "system", Content: system},
			{Role: "user", Content: user},
		},
	})
	if err != nil {
		return "", fmt.Errorf("ai request encode: %w", err)
	}
	url := c.BaseURL + c.Path
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(time.Second):
			}
		}
		content, retryable, err := c.once(ctx, url, payload)
		if err == nil {
			return content, nil
		}
		lastErr = err
		if !retryable {
			return "", err
		}
	}
	return "", lastErr
}

func (c *Client) once(ctx context.Context, url string, payload []byte) (content string, retryable bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return "", false, fmt.Errorf("ai request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", true, fmt.Errorf("ai transport: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", true, fmt.Errorf("ai response read: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		message := strings.TrimSpace(string(body))
		if len(message) > 300 {
			message = message[:300]
		}
		retryable := resp.StatusCode >= 500
		return "", retryable, fmt.Errorf("ai http %d: %s", resp.StatusCode, message)
	}
	var parsed chatResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", false, fmt.Errorf("ai response parse: %w", err)
	}
	if parsed.Error != nil && parsed.Error.Message != "" {
		return "", false, fmt.Errorf("ai provider error: %s", parsed.Error.Message)
	}
	if len(parsed.Choices) == 0 {
		return "", false, fmt.Errorf("ai response has no choices")
	}
	return parsed.Choices[0].Message.Content, false, nil
}
