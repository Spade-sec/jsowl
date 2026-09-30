package aiclient

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestChatSuccess(t *testing.T) {
	var gotAuth, gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"choices":[{"message":{"content":"{\"ok\":true}"}}]}`))
	}))
	defer server.Close()

	client := New(server.URL, "key-123", "test-model", "")
	content, err := client.Chat(context.Background(), "sys", "user prompt")
	if err != nil {
		t.Fatalf("chat: %v", err)
	}
	if content != `{"ok":true}` {
		t.Fatalf("content = %q", content)
	}
	if gotAuth != "Bearer key-123" {
		t.Fatalf("auth header = %q", gotAuth)
	}
	if gotPath != "/chat/completions" {
		t.Fatalf("default path = %q", gotPath)
	}
}

func TestChatRetriesOn5xx(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}]}`))
	}))
	defer server.Close()

	client := New(server.URL, "k", "m", "")
	content, err := client.Chat(context.Background(), "s", "u")
	if err != nil || content != "ok" {
		t.Fatalf("chat after retry = %q, %v", content, err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}
}

func TestChat4xxFailsFast(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":{"message":"bad key"}}`))
	}))
	defer server.Close()

	client := New(server.URL, "k", "m", "")
	_, err := client.Chat(context.Background(), "s", "u")
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("expected 401 error, got %v", err)
	}
	if attempts != 1 {
		t.Fatalf("4xx must not retry, attempts = %d", attempts)
	}
}

func TestChatMalformedJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`not json at all`))
	}))
	defer server.Close()

	client := New(server.URL, "k", "m", "")
	if _, err := client.Chat(context.Background(), "s", "u"); err == nil {
		t.Fatal("malformed response must error")
	}
}

func TestChatEmptyChoices(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"choices":[]}`))
	}))
	defer server.Close()

	client := New(server.URL, "k", "m", "")
	if _, err := client.Chat(context.Background(), "s", "u"); err == nil {
		t.Fatal("empty choices must error")
	}
}

func TestNormalizeFormat(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"":                         FormatOpenAIChat,
		"openai":                   FormatOpenAIChat,
		"OpenAI-Chat":              FormatOpenAIChat,
		"openai-responses":         FormatOpenAIResponses,
		"anthropic":                FormatAnthropic,
		"Anthropic-Messages":       FormatAnthropic,
		"gemini":                   FormatGemini,
		"gemini-native":            FormatGemini,
		"mystery-protocol":         FormatOpenAIChat,
	}
	for input, want := range cases {
		if got := NormalizeFormat(input); got != want {
			t.Errorf("NormalizeFormat(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestAnthropicNative(t *testing.T) {
	var gotPath, gotKey, gotVersion, gotBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotKey = r.Header.Get("x-api-key")
		gotVersion = r.Header.Get("anthropic-version")
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.Write([]byte(`{"content":[{"type":"text","text":"verdict"},{"type":"text","text":"-2"}]}`))
	}))
	defer server.Close()

	client := New(server.URL, "key-a", "claude-x", "anthropic-messages")
	if client.Format != FormatAnthropic {
		t.Fatalf("format = %q", client.Format)
	}
	content, err := client.Chat(context.Background(), "sys", "user prompt")
	if err != nil {
		t.Fatalf("chat: %v", err)
	}
	if content != "verdict-2" {
		t.Fatalf("content = %q", content)
	}
	if gotPath != "/v1/messages" {
		t.Fatalf("path = %q", gotPath)
	}
	if gotKey != "key-a" || gotVersion == "" {
		t.Fatalf("auth = %q version = %q", gotKey, gotVersion)
	}
	if !strings.Contains(gotBody, `"system":"sys"`) || !strings.Contains(gotBody, `"max_tokens":`) {
		t.Fatalf("payload = %s", gotBody)
	}
}

func TestAnthropicEndpointAvoidsDoubleVersion(t *testing.T) {
	t.Parallel()
	client := New("https://relay.example/v1/", "k", "m", FormatAnthropic)
	if got := client.endpoint(); got != "https://relay.example/v1/messages" {
		t.Fatalf("endpoint = %q", got)
	}
}

func TestOpenAIResponses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/responses" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Write([]byte(`{"output":[{"type":"message","content":[{"type":"output_text","text":"done"}]}]}`))
	}))
	defer server.Close()

	client := New(server.URL, "k", "m", FormatOpenAIResponses)
	content, err := client.Chat(context.Background(), "s", "u")
	if err != nil || content != "done" {
		t.Fatalf("chat = %q, %v", content, err)
	}
}

func TestGeminiNative(t *testing.T) {
	var gotKey string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("x-goog-api-key")
		if !strings.HasSuffix(r.URL.Path, "/v1beta/models/m-1:generateContent") {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Write([]byte(`{"candidates":[{"content":{"parts":[{"text":"hi"},{"text":"!"}]}}]}`))
	}))
	defer server.Close()

	client := New(server.URL, "key-g", "m-1", "gemini")
	content, err := client.Chat(context.Background(), "s", "u")
	if err != nil || content != "hi!" {
		t.Fatalf("chat = %q, %v", content, err)
	}
	if gotKey != "key-g" {
		t.Fatalf("api key header = %q", gotKey)
	}
}
