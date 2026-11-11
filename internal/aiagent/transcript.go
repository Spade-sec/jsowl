package aiagent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// transcriptEntry is one line of ai_transcript.jsonl: every model reply,
// tool call and tool result the agent phase produced, for auditability —
// an AI claim in the report must be traceable to the conversation that
// produced it.
type transcriptEntry struct {
	Time    time.Time       `json:"time"`
	Step    int             `json:"step"`
	Role    string          `json:"role"` // model | tool_result | system_note
	Tool    string          `json:"tool,omitempty"`
	Args    json.RawMessage `json:"args,omitempty"`
	Content string          `json:"content"`
}

// transcript appends entries to a JSONL file under the report directory.
// A nil transcript (no report directory) swallows entries: the loop must
// keep working even where nothing can be persisted.
type transcript struct {
	mu   sync.Mutex
	file *os.File
}

func newTranscript(reportDirectory string) *transcript {
	if reportDirectory == "" {
		return &transcript{}
	}
	path := filepath.Join(reportDirectory, "ai_transcript.jsonl")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return &transcript{}
	}
	return &transcript{file: file}
}

func (t *transcript) close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.file != nil {
		t.file.Close()
		t.file = nil
	}
}

// path reports the transcript's location, or "" when nothing was written.
func (t *transcript) path() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.file == nil {
		return ""
	}
	return t.file.Name()
}

func (t *transcript) append(entry transcriptEntry) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.file == nil {
		return
	}
	entry.Time = time.Now()
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	t.file.Write(append(data, '\n'))
}
