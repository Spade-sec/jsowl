package aiagent

import (
	"strings"
	"testing"
)

func TestParsePlanToolCall(t *testing.T) {
	plan, err := ParsePlan(`{"thought":"先看列表","calls":[{"tool":"list_endpoints","args":{"prefix":"/api"}}],"final":null}`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if plan.Thought != "先看列表" || len(plan.Calls) != 1 || plan.Calls[0].Tool != "list_endpoints" {
		t.Fatalf("plan = %+v", plan)
	}
	if plan.Final != nil {
		t.Fatalf("final should be nil")
	}
}

func TestParsePlanFinalWins(t *testing.T) {
	plan, err := ParsePlan(`{"thought":"done","calls":[{"tool":"x","args":{}}],"final":{"reviews":[],"summary":{"overview":"总评"}}}`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if plan.Final == nil || len(plan.Calls) != 0 {
		t.Fatalf("final must win over trailing calls: %+v", plan)
	}
}

func TestParsePlanToleratesFencesAndProse(t *testing.T) {
	reply := "好的，下面是我的计划：\n```json\n{\"thought\":\"a\",\"calls\":[{\"tool\":\"get_findings\",\"args\":{}}]}\n```\n以上。"
	plan, err := ParsePlan(reply)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(plan.Calls) != 1 {
		t.Fatalf("calls = %d", len(plan.Calls))
	}
}

func TestParsePlanNestedBraceInString(t *testing.T) {
	// The thought carries braces inside a string; the balanced-object
	// extractor must not terminate on them.
	reply := `{"thought":"正则 {n} 里的 {\"x\":1} 是字符串","calls":[],"final":{"summary":{}}}`
	plan, err := ParsePlan(reply)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if plan.Final == nil {
		t.Fatalf("final lost")
	}
}

func TestParsePlanRejectsGarbage(t *testing.T) {
	for _, reply := range []string{
		"",
		"我认为这个接口有问题。",
		`[{"index":1}]`, // array, not the plan object
		`{"thought":"只有这一句"}`,
		`{"thought":"a","calls":"不是数组"}`,
	} {
		if _, err := ParsePlan(reply); err == nil {
			t.Fatalf("expected error for %q", reply)
		}
	}
}

func TestParsePlanErrorMentionsCause(t *testing.T) {
	_, err := ParsePlan(`{"thought":"a"}`)
	if err == nil || !strings.Contains(err.Error(), "calls") {
		t.Fatalf("error should explain the empty plan: %v", err)
	}
}
