package aiclient

import (
	"context"
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
